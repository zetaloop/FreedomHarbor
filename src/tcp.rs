use std::{io, net::SocketAddr};

use anyhow::{Context, Result};
use socket2::{Domain, Socket, Type};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tracing::{debug, info, warn};

pub async fn run(addresses: &[SocketAddr]) -> Result<()> {
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
        listeners.spawn(accept(listener));
    }

    while let Some(result) = listeners.join_next().await {
        result.context("listener task failed")??;
    }
    Ok(())
}

async fn accept(listener: TcpListener) -> io::Result<()> {
    loop {
        let (mut client, source) = listener.accept().await?;
        let destination = client.local_addr()?;

        tokio::spawn(async move {
            let result: io::Result<()> = async {
                let mut upstream = TcpStream::connect(destination).await?;
                client.set_nodelay(true)?;
                upstream.set_nodelay(true)?;
                debug!(%source, %destination, "connected");
                let (sent, received) = copy_bidirectional(&mut client, &mut upstream).await?;
                debug!(%source, %destination, sent, received, "connection closed");
                Ok(())
            }
            .await;

            if let Err(error) = result {
                warn!(%source, %destination, %error, "connection failed");
            }
        });
    }
}
