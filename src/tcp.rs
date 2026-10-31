use std::{
    future::{Future, pending},
    io,
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    pin::Pin,
    ptr,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use futures_util::TryFutureExt;
use hyper::body::Bytes;
use socket2::{Domain, SockRef, Socket, Type};
use tokio::{
    io::{AsyncWriteExt, Interest, Ready},
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
    http::Http,
    protocol::{self, Parse, Probe, Protocol},
    starttls,
    tls::Records,
};

pub type Connecting = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;

#[derive(Default)]
pub struct Prefix {
    pub data: Vec<u8>,
    pub sent: usize,
}

pub async fn connect(destination: SocketAddr) -> io::Result<TcpStream> {
    let stream = TcpStream::connect(destination).await?;
    configure(&stream)?;
    Ok(stream)
}

fn configure(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    SockRef::from(stream).set_keepalive(true)
}

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
    mut client: TcpStream,
    destination: SocketAddr,
    http: Arc<Http>,
    tls: bool,
    timeout: Duration,
) -> Result<()> {
    configure(&client)?;
    let mut connecting: Connecting = Box::pin(connect(destination));
    let mut upstream = None;
    let mut request = Prefix::default();
    let mut response = Prefix::default();
    let mut probe = Probe::new(http.enabled, tls);
    let mut deadline = None;
    let mut released = false;
    let mut decision = (!http.enabled && !tls).then_some(Protocol::Tcp);
    let mut hello = None;
    let mut upgrade = None;
    let mut closed = false;
    let mut buffer = [0; 8192];

    while decision.is_none() {
        let forwarding = released && !probe.candidate();
        tokio::select! {
            result = &mut connecting, if upstream.is_none() => {
                upstream = Some(result.context("connect upstream")?);
                debug!(%destination, "connected");
            }
            state = ready(
                Some(&client),
                !forwarding || request.sent == request.data.len(),
                forwarding && response.sent < response.data.len(),
            ) => {
                let state = state.context("poll client")?;
                if state.is_readable() {
                    match client.try_read(&mut buffer) {
                        Ok(0) => {
                            closed = true;
                            decision = Some(Protocol::Tcp);
                        }
                        Ok(count) => {
                            deadline.get_or_insert_with(|| Instant::now() + timeout);
                            request.data.extend_from_slice(&buffer[..count]);
                            decision = probe.feed(&buffer[..count]);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error).context("read client"),
                    }
                }
                if decision.is_none() && !probe.candidate() && state.is_writable() && response.sent < response.data.len() {
                    match client.try_write(&response.data[response.sent..]) {
                        Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)).context("write client"),
                        Ok(count) => response.sent += count,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error).context("write client"),
                    }
                }
            }
            state = ready(
                upstream.as_ref(),
                !forwarding || response.sent == response.data.len(),
                forwarding && request.sent < request.data.len(),
            ) => {
                let state = state.context("poll upstream")?;
                let stream = upstream.as_ref().expect("upstream ready");
                if state.is_readable() {
                    match stream.try_read(&mut buffer) {
                        Ok(0) => {
                            closed = true;
                            decision = Some(Protocol::Tcp);
                        }
                        Ok(count) => {
                            deadline.get_or_insert_with(|| Instant::now() + timeout);
                            response.data.extend_from_slice(&buffer[..count]);
                            decision = if http.enabled {
                                protocol::response(&response.data)
                            } else {
                                Some(Protocol::Tcp)
                            };
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error).context("read upstream"),
                    }
                }
                if decision.is_none() && state.is_writable() && request.sent < request.data.len() {
                    match stream.try_write(&request.data[request.sent..]) {
                        Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)).context("write upstream"),
                        Ok(count) => request.sent += count,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error).context("write upstream"),
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
            match Records::parse(&request.data) {
                Ok(parsed) if parsed.hello.ready => hello = Some(parsed),
                Ok(_) | Err(Parse::Incomplete) => decision = None,
                Err(Parse::Invalid) => decision = Some(Protocol::Tcp),
            }
        }
        if tls && !closed && decision == Some(Protocol::Tcp) {
            released = true;
            probe = Probe::Done(Protocol::Tcp);
            match starttls::detect(&request.data, &response.data) {
                Ok(protocol) => upgrade = protocol,
                Err(Parse::Incomplete) => decision = None,
                Err(Parse::Invalid) => {}
            }
        }
    }

    if let Some(hello) = hello {
        debug!(%destination, "TLS detected");
        hello.fragment(&mut request.data);
    }
    if decision == Some(Protocol::Mmtls) {
        debug!(%destination, "MMTLS detected");
    }

    if decision != Some(Protocol::Http) {
        let mut upstream = match upstream {
            Some(stream) => stream,
            None => connecting.await.context("connect upstream")?,
        };
        let sent = request.sent;
        let received = response.sent;
        let (forwarded, returned) = if let Some(protocol) = upgrade {
            starttls::forward(protocol, &mut client, &mut upstream, request, response).await?
        } else {
            let (client_read, client_write) = client.split();
            let (upstream_read, upstream_write) = upstream.split();
            tokio::try_join!(
                transfer(
                    client_read,
                    upstream_write,
                    Bytes::from(request.data).slice(sent..),
                )
                .map_err(|error| error.context("client to upstream")),
                transfer(
                    upstream_read,
                    client_write,
                    Bytes::from(response.data).slice(received..),
                )
                .map_err(|error| error.context("upstream to client")),
            )?
        };
        debug!(
            %destination,
            sent = forwarded + sent as u64,
            received = returned + received as u64,
            "connection closed"
        );
        return Ok(());
    }

    debug!(%destination, "HTTP detected");
    let initial = if let Some(stream) = upstream {
        Box::pin(async move { Ok(stream) }) as Connecting
    } else {
        connecting
    };
    http.serve(client, destination, initial, request, response)
        .await
}

pub async fn transfer(
    reader: ReadHalf<'_>,
    mut writer: WriteHalf<'_>,
    prefix: Bytes,
) -> Result<u64> {
    let mut total = prefix.len() as u64;
    writer.write_all(&prefix).await.context("write prefix")?;
    drop(prefix);

    let source = reader.as_ref();
    if source.peek(&mut [0]).await.context("read")? == 0 {
        writer.shutdown().await.context("shutdown write")?;
        return Ok(total);
    }

    let (pipe_read, pipe_write) = io::pipe().context("create pipe")?;
    loop {
        let mut pending = source
            .async_io(Interest::READABLE, || {
                splice(source.as_fd(), pipe_write.as_fd(), isize::MAX as usize)
            })
            .await
            .context("read")?;
        if pending == 0 {
            writer.shutdown().await.context("shutdown write")?;
            return Ok(total);
        }

        let destination = writer.as_ref();
        while pending != 0 {
            let count = destination
                .async_io(Interest::WRITABLE, || {
                    splice(pipe_read.as_fd(), destination.as_fd(), pending)
                })
                .await
                .context("write")?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero)).context("write");
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

async fn ready(stream: Option<&TcpStream>, read: bool, write: bool) -> io::Result<Ready> {
    let interest = match (read, write) {
        (true, true) => Some(Interest::READABLE | Interest::WRITABLE),
        (true, false) => Some(Interest::READABLE),
        (false, true) => Some(Interest::WRITABLE),
        (false, false) => None,
    };
    match (stream, interest) {
        (Some(stream), Some(interest)) => stream.ready(interest).await,
        _ => pending().await,
    }
}
