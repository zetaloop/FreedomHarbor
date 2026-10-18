mod stream;

use std::{
    convert::Infallible,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll},
};

use anyhow::{Context as _, Result};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
    header::{
        CACHE_CONTROL, CONNECTION, HOST, LOCATION, TE, TRANSFER_ENCODING, UPGRADE, USER_AGENT,
    },
    uri::{Authority, Scheme},
};
use http_body_util::BodyExt;
use hyper::{
    body::{Bytes, Incoming},
    service::service_fn,
    upgrade,
};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use tokio::{
    io::{AsyncReadExt, copy_bidirectional},
    net::TcpStream,
};
use tower_service::Service;
use tracing::{debug, warn};

use crate::{
    body::{self, Body, ResponseBody},
    config, https,
    probe::Probe,
    protocol::{self, Protocol},
    tcp::{self, Prefix},
};

use stream::Stream;

type Connecting = Pin<Box<dyn Future<Output = io::Result<Stream>> + Send>>;

type Initial = Arc<Mutex<Option<Connecting>>>;
type PlainClient = Client<Connector, Body>;
type SecureClient = Client<https::Connector, Body>;

pub struct Http {
    pub enabled: bool,
    https: Option<https::Https>,
    probe: Option<Probe>,
    user_agent: Option<HeaderValue>,
}

#[derive(Clone)]
struct Connector {
    destination: SocketAddr,
    initial: Initial,
    proxied: bool,
}

impl Service<Uri> for Connector {
    type Response = TokioIo<Stream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let initial = self
            .initial
            .lock()
            .expect("connection lock poisoned")
            .take();
        let destination = self.destination;
        let proxied = self.proxied;
        Box::pin(async move {
            let mut stream = match initial {
                Some(connecting) => connecting.await?,
                None => Stream::new(tcp::connect(destination).await?),
            };
            stream.proxied = proxied;
            Ok(TokioIo::new(stream))
        })
    }
}

struct Clients {
    initial: Initial,
    plain: [PlainClient; 2],
    secure: Option<[(SecureClient, https::Connector); 2]>,
}

impl Http {
    pub fn new(config: &config::Http) -> Result<Self> {
        Ok(Self {
            enabled: config.enabled,
            https: (config.enabled && config.upgrade)
                .then(|| https::Https::new(config))
                .transpose()?,
            probe: (config.enabled && config.probe.enabled)
                .then(|| Probe::new(&config.probe))
                .transpose()?,
            user_agent: (config.enabled && config.normalize)
                .then(|| {
                    HeaderValue::from_str(&config.user_agent).context("invalid http.user_agent")
                })
                .transpose()?,
        })
    }

    pub async fn serve(
        self: Arc<Self>,
        client: TcpStream,
        destination: SocketAddr,
        mut connecting: tcp::Connecting,
        request: Prefix,
        mut response: Prefix,
    ) -> Result<()> {
        if response.sent != 0
            && !b"HTTP/".starts_with(&response.data)
            && !response.data.starts_with(b"HTTP/")
        {
            if response.data.len() < 9 {
                let start = response.data.len();
                response.data.resize(9, 0);
                let mut upstream = connecting.await?;
                upstream.read_exact(&mut response.data[start..]).await?;
                connecting = Box::pin(async move { Ok(upstream) });
            }
            if protocol::response(&response.data) != Some(Protocol::Http) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HTTP server preface",
                )
                .into());
            }
        }
        let mut client = Stream::new(client);
        client.resume(&response.data, response.sent);
        client.prefix = Bytes::from(request.data);
        let connecting: Connecting = if request.sent != 0 {
            drop(connecting);
            Box::pin(async move { tcp::connect(destination).await.map(Stream::new) })
        } else {
            Box::pin(async move {
                let mut stream = Stream::new(connecting.await?);
                stream.prefix = Bytes::from(response.data);
                Ok(stream)
            })
        };
        let source = client.socket.peer_addr()?;
        let initial = Arc::new(Mutex::new(Some(connecting)));
        let clients = OnceLock::new();
        let preserve_case = self.user_agent.is_none();
        let service = service_fn(move |request: Request<Incoming>| {
            let clients = clients.get_or_init(|| {
                let mut builder = Client::builder(TokioExecutor::new());
                builder.set_host(false).http1_preserve_header_case(true);
                let secure = self.https.as_ref().map(|https| {
                    [false, true].map(|http2| {
                        let connector = https.connector(destination, http2);
                        (builder.build(connector.clone()), connector)
                    })
                });
                builder.http2_only(request.version() == Version::HTTP_2);
                let plain = [false, true].map(|proxied| {
                    builder.build(Connector {
                        destination,
                        initial: Arc::clone(&initial),
                        proxied,
                    })
                });
                Arc::new(Clients {
                    initial: Arc::clone(&initial),
                    plain,
                    secure,
                })
            });
            let clients = Arc::clone(clients);
            let http = Arc::clone(&self);

            async move {
                let response = match http.forward(request, source, destination, clients).await {
                    Ok(response) => response,
                    Err(error) => {
                        warn!(%destination, ?error, "HTTP request failed");
                        let mut response = Response::new(body::empty());
                        *response.status_mut() = StatusCode::BAD_GATEWAY;
                        response
                    }
                };
                Ok::<_, Infallible>(response)
            }
        });
        let mut server = auto::Builder::new(TokioExecutor::new());
        server
            .http1()
            .half_close(true)
            .preserve_header_case(preserve_case)
            .header_read_timeout(None);
        server.http2().enable_connect_protocol();
        server
            .serve_connection_with_upgrades(TokioIo::new(client), service)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        Ok(())
    }

    async fn forward(
        &self,
        mut request: Request<Incoming>,
        source: SocketAddr,
        destination: SocketAddr,
        clients: Arc<Clients>,
    ) -> Result<Response<ResponseBody>> {
        let proxied = request.version() != Version::HTTP_2 && request.uri().scheme().is_some();
        let http2 = !request.headers().contains_key(UPGRADE);
        let connect = request.method() == Method::CONNECT;
        let extended = request.extensions().get::<hyper::ext::Protocol>().is_some();
        let switching = connect || connection_upgrade(request.headers());
        let client_upgrade = switching.then(|| upgrade::on(&mut request));
        let secure = clients
            .secure
            .as_ref()
            .filter(|_| !proxied)
            .map(|clients| &clients[usize::from(http2)]);
        let mut parts = request.uri().clone().into_parts();
        let host = match &parts.authority {
            Some(authority) => authority.clone(),
            None => match request
                .headers()
                .get(HOST)
                .filter(|value| !value.is_empty())
            {
                Some(host) => host.to_str()?.parse().context("invalid HTTP host")?,
                None => destination.to_string().parse()?,
            },
        };
        parts.authority = Some(host.clone());
        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse()?);
        }
        if parts.scheme.is_none() {
            parts.scheme = Some(Scheme::HTTP);
        }
        *request.uri_mut() = Uri::from_parts(parts)?;
        let exchange = self
            .probe
            .as_ref()
            .map(|probe| probe.request(&mut request, source, destination));
        if let Some(exchange) = exchange.as_ref()
            && exchange.blocked
        {
            return Ok(self
                .probe
                .as_ref()
                .expect("probe enabled")
                .block(request.into_body(), exchange)
                .await);
        }
        hop_headers(request.headers_mut(), true)?;
        let request = request.map(Body::new);
        let send = async |mut request: Request<Body>| {
            if let Some(user_agent) = &self.user_agent {
                normalize(request.headers_mut(), user_agent);
            }
            clients.plain[usize::from(proxied)].request(request).await
        };
        let (mut response, encrypted) = if let Some((secure, connector)) = secure
            && (!connect || extended)
            && request.uri().scheme() == Some(&Scheme::HTTP)
        {
            let mut parts = request.uri().clone().into_parts();
            let target = authority(&host)?;
            parts.authority = Some(target.clone());
            parts.scheme = Some(Scheme::HTTPS);
            let uri = Uri::from_parts(parts)?;
            let redirect = !switching
                && matches!(*request.method(), Method::GET | Method::HEAD)
                && request
                    .headers()
                    .get("upgrade-insecure-requests")
                    .is_some_and(|value| value == "1");
            if redirect {
                if connector.clone().available(&uri).await {
                    clients
                        .initial
                        .lock()
                        .expect("connection lock poisoned")
                        .take();
                    let mut response = Response::new(body::empty());
                    *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
                    response
                        .headers_mut()
                        .insert(LOCATION, uri.to_string().parse()?);
                    response
                        .headers_mut()
                        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
                    return Ok(response);
                }
                (send(request).await?, false)
            } else {
                let mut encrypted = request.clone();
                *encrypted.uri_mut() = uri.clone();
                if encrypted.headers().contains_key(HOST) {
                    encrypted
                        .headers_mut()
                        .insert(HOST, HeaderValue::from_str(target.as_str())?);
                }
                if !extended {
                    *encrypted.version_mut() = Version::HTTP_11;
                }
                match secure.request(encrypted).await {
                    Ok(response) => {
                        clients
                            .initial
                            .lock()
                            .expect("connection lock poisoned")
                            .take();
                        debug!(%host, "using HTTPS upstream");
                        (response, true)
                    }
                    Err(error) if error.is_connect() => {
                        debug!(%host, ?error, "using HTTP upstream");
                        (send(request).await?, false)
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        } else {
            (send(request).await?, false)
        };

        if (response.status() == StatusCode::SWITCHING_PROTOCOLS
            || (connect && response.status().is_success()))
            && let Some(client_upgrade) = client_upgrade
        {
            let upstream_upgrade = upgrade::on(&mut response);
            tokio::spawn(async move {
                let result = async {
                    let (client, upstream) = tokio::try_join!(client_upgrade, upstream_upgrade)?;
                    copy_bidirectional(&mut TokioIo::new(client), &mut TokioIo::new(upstream))
                        .await?;
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(error) = result {
                    warn!(?error, "HTTP tunnel failed");
                }
            });
        }
        let mut response = match (&self.probe, exchange) {
            (Some(probe), Some(exchange)) => probe.response(response, exchange).await?,
            _ => response.map(|body| body.map_err(anyhow::Error::from).boxed_unsync()),
        };
        hop_headers(response.headers_mut(), false)?;
        if !encrypted && self.user_agent.is_some() {
            response.headers_mut().remove("accept-ch");
            response.headers_mut().remove("critical-ch");
        }
        Ok(response)
    }
}

fn authority(value: &Authority) -> Result<Authority> {
    if value.port_u16() == Some(80) {
        Ok(value.host().parse()?)
    } else {
        Ok(value.clone())
    }
}

fn normalize(headers: &mut HeaderMap, user_agent: &HeaderValue) {
    headers.insert(USER_AGENT, user_agent.clone());
    let mut fields: Vec<_> = headers
        .iter()
        .filter(|(name, _)| {
            !name.as_str().starts_with("sec-ch-")
                && !matches!(
                    name.as_str(),
                    "forwarded"
                        | "via"
                        | "x-forwarded-for"
                        | "x-real-ip"
                        | "device-memory"
                        | "dpr"
                        | "width"
                        | "viewport-width"
                        | "rtt"
                        | "downlink"
                        | "ect"
                        | "save-data"
                )
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    fields.sort_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));
    let mut normalized = HeaderMap::with_capacity(fields.len());
    for (name, value) in fields {
        normalized.append(name, value);
    }
    *headers = normalized;
}

fn connection_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(UPGRADE)
        && headers.get_all(CONNECTION).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
}

fn hop_headers(headers: &mut HeaderMap, request: bool) -> Result<()> {
    let upgrades: Vec<_> = if connection_upgrade(headers) {
        headers.get_all(UPGRADE).iter().cloned().collect()
    } else {
        Vec::new()
    };
    let trailers = request
        && headers.get_all(TE).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("trailers"))
            })
        });
    let mut nominated = Vec::new();
    for value in headers.get_all(CONNECTION) {
        for name in value
            .to_str()?
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            nominated.push(HeaderName::from_bytes(name.as_bytes())?);
        }
    }
    for name in nominated {
        headers.remove(name);
    }
    for name in [CONNECTION, TE, TRANSFER_ENCODING] {
        headers.remove(name);
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
    if !upgrades.is_empty() {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        for upgrade in upgrades {
            headers.append(UPGRADE, upgrade);
        }
    }
    if trailers {
        headers.insert(TE, HeaderValue::from_static("trailers"));
    }
    Ok(())
}
