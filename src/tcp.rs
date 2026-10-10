use std::{future::pending, io, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use hyper::body::Bytes;
use socket2::{Domain, Socket, Type};
use tokio::{
    io::{AsyncReadExt, Interest, Ready, copy_bidirectional},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{Instant, sleep_until},
};
use tracing::{debug, info, warn};

use crate::{
    http::{Connecting, Http},
    protocol::{self, Probe, Protocol},
    stream::Stream,
};

pub async fn run(addresses: &[SocketAddr], http: Arc<Http>) -> Result<()> {
    let mut listeners = JoinSet::new();

    for &address in addresses {
        let socket = Socket::new(Domain::for_address(address), Type::STREAM, None)?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        match address {
            SocketAddr::V4(_) => socket.set_ip_transparent_v4(true)?,
            SocketAddr::V6(_) => {
                socket.set_only_v6(true)?;
                socket.set_ip_transparent_v6(true)?;
            }
        }
        socket
            .bind(&address.into())
            .with_context(|| format!("failed to bind {address}"))?;
        socket.listen(libc::SOMAXCONN)?;
        let listener = TcpListener::from_std(socket.into())?;
        info!(%address, "listening");
        listeners.spawn(accept(listener, Arc::clone(&http)));
    }

    while let Some(result) = listeners.join_next().await {
        result.context("listener task failed")??;
    }
    pending().await
}

async fn accept(listener: TcpListener, http: Arc<Http>) -> io::Result<()> {
    loop {
        let (client, source) = listener.accept().await?;
        let destination = client.local_addr()?;
        let http = Arc::clone(&http);

        tokio::spawn(async move {
            if let Err(error) = forward(client, destination, http).await {
                warn!(%source, %destination, ?error, "connection failed");
            }
        });
    }
}

async fn forward(client: TcpStream, destination: SocketAddr, http: Arc<Http>) -> Result<()> {
    let mut client = Stream::new(client)?;
    let mut connecting: Connecting = Box::pin(Stream::connect(destination));
    let mut upstream = None;
    let mut request = Vec::new();
    let mut response = Vec::new();
    let mut sent = 0;
    let mut received = 0;
    let mut probe = Probe::default();
    let mut deadline = None;
    let mut released = false;
    let mut decision = (!http.enabled).then_some(Protocol::Tcp);
    let mut buffer = [0; 8192];

    while decision.is_none() {
        tokio::select! {
            result = &mut connecting, if upstream.is_none() => {
                upstream = Some(result?);
                debug!(%destination, "connected");
            }
            state = ready(
                Some(&client),
                !released || sent == request.len(),
                released && received < response.len(),
            ) => {
                let state = state?;
                if state.is_readable() {
                    match client.socket.try_read(&mut buffer) {
                        Ok(0) => decision = Some(Protocol::Tcp),
                        Ok(count) => {
                            deadline.get_or_insert_with(|| Instant::now() + http.timeout);
                            request.extend_from_slice(&buffer[..count]);
                            decision = probe.feed(&buffer[..count]);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if decision.is_none() && state.is_writable() && received < response.len() {
                    match client.socket.try_write(&response[received..]) {
                        Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                        Ok(count) => received += count,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            state = ready(
                upstream.as_ref(),
                !released || received == response.len(),
                released && sent < request.len(),
            ) => {
                let state = state?;
                let stream = upstream.as_ref().expect("upstream ready");
                if state.is_readable() {
                    match stream.socket.try_read(&mut buffer) {
                        Ok(0) => decision = Some(Protocol::Tcp),
                        Ok(count) => {
                            deadline.get_or_insert_with(|| Instant::now() + http.timeout);
                            response.extend_from_slice(&buffer[..count]);
                            decision = protocol::response(&response);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if decision.is_none() && state.is_writable() && sent < request.len() {
                    match stream.socket.try_write(&request[sent..]) {
                        Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                        Ok(count) => sent += count,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            _ = async {
                match deadline {
                    Some(deadline) => sleep_until(deadline).await,
                    None => pending().await,
                }
            }, if !released => released = true,
        }
    }

    if decision == Some(Protocol::Tcp) {
        let mut upstream = match upstream {
            Some(stream) => stream,
            None => connecting.await?,
        };
        client.prefix = Bytes::from(request).slice(sent..);
        upstream.prefix = Bytes::from(response).slice(received..);
        let (forwarded, returned) = copy_bidirectional(&mut client, &mut upstream).await?;
        debug!(
            %destination,
            sent = forwarded + sent as u64,
            received = returned + received as u64,
            "connection closed"
        );
        return Ok(());
    }

    debug!(%destination, "HTTP detected");
    if received != 0 && !b"HTTP/".starts_with(&response) && !response.starts_with(b"HTTP/") {
        if response.len() < 9 {
            let start = response.len();
            response.resize(9, 0);
            upstream
                .as_mut()
                .expect("received upstream data")
                .read_exact(&mut response[start..])
                .await?;
        }
        if protocol::response(&response) != Some(Protocol::Http) {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP server preface").into(),
            );
        }
    }
    client.resume(&response, received);
    client.prefix = Bytes::from(request);
    let initial = if sent != 0 {
        drop(upstream);
        Box::pin(Stream::connect(destination)) as Connecting
    } else if let Some(mut stream) = upstream {
        stream.prefix = Bytes::from(response);
        Box::pin(async move { Ok(stream) }) as Connecting
    } else {
        connecting
    };
    http.serve(client, destination, initial).await
}

async fn ready(stream: Option<&Stream>, read: bool, write: bool) -> io::Result<Ready> {
    let interest = match (read, write) {
        (true, true) => Some(Interest::READABLE | Interest::WRITABLE),
        (true, false) => Some(Interest::READABLE),
        (false, true) => Some(Interest::WRITABLE),
        (false, false) => None,
    };
    match (stream, interest) {
        (Some(stream), Some(interest)) => stream.socket.ready(interest).await,
        _ => pending().await,
    }
}
