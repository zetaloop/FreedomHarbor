use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result};
use http::{Uri, uri::Authority};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector, HttpsConnectorBuilder, MaybeHttpsStream};
use hyper_util::rt::TokioIo;
use moka::future::Cache;
use tokio::{net::TcpStream, time::timeout};
use tower_service::Service;
use tracing::debug;

use crate::{config, tcp};

type Key = (SocketAddr, Authority, bool);
type Connection = MaybeHttpsStream<TokioIo<TcpStream>>;

pub struct Https {
    tls: rustls::ClientConfig,
    timeout: Duration,
    cache: Cache<Key, bool>,
}

#[derive(Clone)]
pub struct Connector {
    inner: HttpsConnector<Tcp>,
    address: SocketAddr,
    http2: bool,
    timeout: Duration,
    cache: Cache<Key, bool>,
}

#[derive(Clone)]
struct Tcp(SocketAddr);

impl Service<Uri> for Tcp {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mut destination = self.0;
        destination.set_port(uri.port_u16().unwrap_or(443));
        Box::pin(async move { tcp::connect(destination).await.map(TokioIo::new) })
    }
}

impl Https {
    pub fn new(config: &config::Http) -> Result<Self> {
        let tls = rustls::ClientConfig::builder()
            .with_native_roots()
            .context("failed to load TLS trust roots")?
            .with_no_client_auth();
        Ok(Self {
            tls,
            timeout: Duration::from_millis(config.tls_timeout_ms),
            cache: Cache::builder()
                .time_to_live(Duration::from_millis(config.cache_ttl_ms))
                .build(),
        })
    }

    pub fn connector(&self, address: SocketAddr, http2: bool) -> Connector {
        let builder = HttpsConnectorBuilder::new()
            .with_tls_config(self.tls.clone())
            .https_only();
        let inner = if http2 {
            builder.enable_all_versions().wrap_connector(Tcp(address))
        } else {
            builder.enable_http1().wrap_connector(Tcp(address))
        };
        Connector {
            inner,
            address,
            http2,
            timeout: self.timeout,
            cache: self.cache.clone(),
        }
    }
}

impl Connector {
    fn key(&self, uri: &Uri) -> Key {
        let mut address = self.address;
        address.set_port(uri.port_u16().unwrap_or(443));
        (
            address,
            uri.authority().expect("HTTPS authority").clone(),
            self.http2,
        )
    }

    pub async fn available(&mut self, uri: &Uri) -> bool {
        match self.cache.get(&self.key(uri)).await {
            Some(available) => available,
            None => self.call(uri.clone()).await.is_ok(),
        }
    }
}

impl Service<Uri> for Connector {
    type Response = Connection;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Connection>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let key = self.key(&uri);
        let cache = self.cache.clone();
        let deadline = self.timeout;
        let mut inner = self.inner.clone();
        Box::pin(async move {
            if cache.get(&key).await == Some(false) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "HTTPS temporarily unavailable",
                ));
            }
            let result = match timeout(deadline, inner.call(uri)).await {
                Ok(result) => result.map_err(io::Error::other),
                Err(error) => Err(io::Error::new(io::ErrorKind::TimedOut, error)),
            };
            cache.insert(key.clone(), result.is_ok()).await;
            if let Err(error) = &result {
                debug!(address = %key.0, host = %key.1, %error, "HTTPS connection failed");
            }
            result
        })
    }
}
