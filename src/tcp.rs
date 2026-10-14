use std::{
    future::pending,
    io,
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    ptr,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use hyper::body::Bytes;
use socket2::{Domain, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest, Ready},
    net::{
        TcpListener, TcpStream,
        tcp::{ReadHalf, WriteHalf},
    },
    task::JoinSet,
    time::{Instant, sleep, sleep_until},
};
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    http::{Connecting, Http},
    protocol::{self, Probe, Protocol},
    stream::Stream,
    tls::{Parse, Records},
};

pub async fn run(config: &Config, http: Arc<Http>) -> Result<()> {
    let mut listeners = JoinSet::new();
    let timeout = Duration::from_millis(config.sniff_timeout_ms);

    for &address in &config.listen {
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
        listeners.spawn(accept(listener, Arc::clone(&http), config.tls, timeout));
    }

    while let Some(result) = listeners.join_next().await {
        result.context("listener task failed")?;
    }
    pending().await
}

async fn accept(listener: TcpListener, http: Arc<Http>, tls: bool, timeout: Duration) {
    loop {
        let (client, source) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::Interrupted
                ) =>
            {
                debug!(?error, "connection interrupted during accept");
                continue;
            }
            Err(error) => {
                warn!(?error, "failed to accept connection");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let destination = match client.local_addr() {
            Ok(destination) => destination,
            Err(error) => {
                warn!(%source, ?error, "failed to read destination");
                continue;
            }
        };
        let http = Arc::clone(&http);

        tokio::spawn(async move {
            if let Err(error) = forward(client, destination, http, tls, timeout).await {
                warn!(%source, %destination, ?error, "connection failed");
            }
        });
    }
}

async fn forward(
    client: TcpStream,
    destination: SocketAddr,
    http: Arc<Http>,
    tls: bool,
    timeout: Duration,
) -> Result<()> {
    let mut client = Stream::new(client)?;
    let mut connecting: Connecting = Box::pin(Stream::connect(destination));
    let mut upstream = None;
    let mut request = Vec::new();
    let mut response = Vec::new();
    let mut sent = 0;
    let mut received = 0;
    let mut probe = Probe::new(http.enabled, tls);
    let mut deadline = None;
    let mut released = false;
    let mut decision = (!http.enabled && !tls).then_some(Protocol::Tcp);
    let mut hello = None;
    let mut buffer = [0; 8192];

    while decision.is_none() {
        let forwarding = released && !probe.candidate();
        tokio::select! {
            result = &mut connecting, if upstream.is_none() => {
                upstream = Some(result?);
                debug!(%destination, "connected");
            }
            state = ready(
                Some(&client),
                !forwarding || sent == request.len(),
                forwarding && received < response.len(),
            ) => {
                let state = state?;
                if state.is_readable() {
                    match client.socket.try_read(&mut buffer) {
                        Ok(0) => decision = Some(Protocol::Tcp),
                        Ok(count) => {
                            deadline.get_or_insert_with(|| Instant::now() + timeout);
                            request.extend_from_slice(&buffer[..count]);
                            decision = probe.feed(&buffer[..count]);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if decision.is_none() && !probe.candidate() && state.is_writable() && received < response.len() {
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
                !forwarding || received == response.len(),
                forwarding && sent < request.len(),
            ) => {
                let state = state?;
                let stream = upstream.as_ref().expect("upstream ready");
                if state.is_readable() {
                    match stream.socket.try_read(&mut buffer) {
                        Ok(0) => decision = Some(Protocol::Tcp),
                        Ok(count) => {
                            deadline.get_or_insert_with(|| Instant::now() + timeout);
                            response.extend_from_slice(&buffer[..count]);
                            decision = if http.enabled {
                                protocol::response(&response)
                            } else {
                                Some(Protocol::Tcp)
                            };
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
            }, if !released && !probe.candidate() => released = true,
        }
        if decision == Some(Protocol::Tls) {
            match Records::parse(&request) {
                Ok(parsed) if parsed.hello.ready => hello = Some(parsed),
                Ok(_) | Err(Parse::Incomplete) => decision = None,
                Err(Parse::Invalid) => decision = Some(Protocol::Tcp),
            }
        }
    }

    if let Some(hello) = hello {
        debug!(%destination, "TLS detected");
        hello.fragment(&mut request);
    }

    if decision != Some(Protocol::Http) {
        let mut upstream = match upstream {
            Some(stream) => stream,
            None => connecting.await?,
        };
        let (client_read, client_write) = client.socket.split();
        let (upstream_read, upstream_write) = upstream.socket.split();
        let (forwarded, returned) = tokio::try_join!(
            transfer(
                client_read,
                upstream_write,
                Bytes::from(request).slice(sent..),
            ),
            transfer(
                upstream_read,
                client_write,
                Bytes::from(response).slice(received..),
            ),
        )?;
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

async fn transfer(
    reader: ReadHalf<'_>,
    mut writer: WriteHalf<'_>,
    prefix: Bytes,
) -> io::Result<u64> {
    let mut total = prefix.len() as u64;
    writer.write_all(&prefix).await?;
    drop(prefix);

    let source = reader.as_ref();
    if source.peek(&mut [0]).await? == 0 {
        writer.shutdown().await?;
        return Ok(total);
    }

    let (pipe_read, pipe_write) = io::pipe()?;
    loop {
        let mut pending = source
            .async_io(Interest::READABLE, || {
                splice(source.as_fd(), pipe_write.as_fd(), isize::MAX as usize)
            })
            .await?;
        if pending == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }

        let destination = writer.as_ref();
        while pending != 0 {
            let count = destination
                .async_io(Interest::WRITABLE, || {
                    splice(pipe_read.as_fd(), destination.as_fd(), pending)
                })
                .await?;
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            pending -= count;
            total += count as u64;
        }
    }
}

fn splice(source: BorrowedFd<'_>, destination: BorrowedFd<'_>, length: usize) -> io::Result<usize> {
    loop {
        let count = unsafe {
            libc::splice(
                source.as_raw_fd(),
                ptr::null_mut(),
                destination.as_raw_fd(),
                ptr::null_mut(),
                length,
                libc::SPLICE_F_NONBLOCK,
            )
        };
        if count >= 0 {
            return Ok(count as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
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
