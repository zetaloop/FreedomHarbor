use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use anyhow::{Context, Result};
use futures_util::{StreamExt, TryStreamExt, stream};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version,
    header::{CACHE_CONTROL, CONTENT_RANGE, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE},
};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body as _, Frame, Incoming};
use lol_html::Selector;
use regex::{Regex, RegexSet};
use serde::Serialize;
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    sync::oneshot,
};
use tokio_util::io::ReaderStream;
use tracing::{info, warn};
use url::Url;

use crate::{
    body::{self, ResponseBody},
    config, html,
    sample::Sample,
};

pub struct Rule {
    pub name: String,
    scope: Option<Regex>,
    urls: RegexSet,
    pub elements: Vec<Selector>,
    pub scripts: RegexSet,
    cookies: RegexSet,
}

pub struct Probe {
    rules: Vec<Arc<Rule>>,
    samples: Option<PathBuf>,
}

pub struct Exchange {
    pub record: Arc<Record>,
    pub rules: Vec<Arc<Rule>>,
    pub blocked: bool,
}

#[derive(Serialize)]
pub struct Hit {
    pub rule: String,
    pub action: &'static str,
}

pub struct Record {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub uri: String,
    pub method: Method,
    pub version: Version,
    pub headers: HeaderMap,
    time: SystemTime,
    hits: Mutex<Vec<Hit>>,
}

impl Record {
    pub fn new<B>(request: &Request<B>, source: SocketAddr, destination: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            source,
            destination,
            uri: request.uri().to_string(),
            method: request.method().clone(),
            version: request.version(),
            headers: request.headers().clone(),
            time: SystemTime::now(),
            hits: Mutex::new(Vec::new()),
        })
    }

    pub fn hit(&self, rule: &str, action: &'static str) {
        let mut hits = self.hits.lock().expect("record lock poisoned");
        if hits
            .iter()
            .any(|hit| hit.rule == rule && hit.action == action)
        {
            return;
        }
        hits.push(Hit {
            rule: rule.into(),
            action,
        });
        info!(source = %self.source, destination = %self.destination, uri = %self.uri, rule, action, "probe matched");
    }

    pub fn matched(&self) -> bool {
        !self.hits.lock().expect("record lock poisoned").is_empty()
    }

    pub fn metadata(&self, complete: bool, error: Option<String>) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(&serde_json::json!({
            "time": self.time,
            "source": self.source,
            "destination": self.destination,
            "uri": self.uri,
            "hits": *self.hits.lock().expect("record lock poisoned"),
            "complete": complete,
            "error": error,
        }))?)
    }
}

impl Probe {
    pub fn new(config: &config::Probe) -> Result<Self> {
        let rules = config
            .rules
            .iter()
            .map(|rule| {
                let compiled = (|| {
                    Ok::<_, anyhow::Error>(Arc::new(Rule {
                        name: rule.name.clone(),
                        scope: rule.scope.as_deref().map(Regex::new).transpose()?,
                        urls: RegexSet::new(&rule.urls)?,
                        elements: rule
                            .elements
                            .iter()
                            .map(|value| value.parse())
                            .collect::<Result<_, _>>()?,
                        scripts: RegexSet::new(&rule.scripts)?,
                        cookies: RegexSet::new(&rule.cookies)?,
                    }))
                })();
                compiled.with_context(|| format!("invalid probe rule {}", rule.name))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            rules,
            samples: config.capture.then(|| config.samples.clone()),
        })
    }

    pub fn request(
        &self,
        request: &mut Request<Incoming>,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Exchange {
        let record = Record::new(request, source, destination);
        let rules: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| {
                rule.scope
                    .as_ref()
                    .is_none_or(|scope| scope.is_match(&record.uri))
            })
            .cloned()
            .collect();
        let blocked = match_url(&record.uri, &rules, &record);
        cookies(request.headers_mut(), COOKIE, &rules, &record);
        Exchange {
            record,
            rules,
            blocked,
        }
    }

    pub fn block(&self, body: Incoming, exchange: &Exchange) -> Response<ResponseBody> {
        let directory = self.samples.clone();
        let record = Arc::clone(&exchange.record);
        tokio::spawn(async move {
            let mut sample = Self::sample(directory, &record, None).await;
            let result = receive(body, None, &mut sample, &record).await;
            let error = result.as_ref().err().map(ToString::to_string);
            finish(sample, &record, result.ok(), error).await;
        });
        blocked()
    }

    pub fn response(
        &self,
        response: Response<Incoming>,
        exchange: Exchange,
    ) -> Response<ResponseBody> {
        let (mut parts, body) = response.into_parts();
        let original = self.samples.as_ref().map(|_| parts.clone());
        let Exchange { record, rules, .. } = exchange;
        cookies(&mut parts.headers, SET_COOKIE, &rules, &record);
        let redirect = parts.status.is_redirection()
            && parts
                .headers
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|location| Url::parse(&record.uri).ok()?.join(location).ok())
                .is_some_and(|location| match_url(location.as_str(), &rules, &record));
        let media = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<mime::Mime>().ok())
            .filter(|media| media.essence_str() == "text/html" && html::encoding(media).is_some());
        let filtering = media.is_some()
            && !redirect
            && !body.is_end_stream()
            && !parts.headers.contains_key(CONTENT_RANGE)
            && rules
                .iter()
                .any(|rule| !rule.elements.is_empty() || !rule.scripts.is_empty());
        let codings = if filtering {
            html::codings(&parts.headers)
        } else {
            None
        };
        let filtering = codings.is_some();

        if !record.matched() && codings.is_none() {
            return Response::from_parts(parts, body.map_err(anyhow::Error::from).boxed_unsync());
        }
        let directory = self.samples.clone();
        if redirect {
            tokio::spawn(async move {
                let mut sample = Self::sample(directory, &record, original).await;
                let result = receive(body, None, &mut sample, &record).await;
                let error = result.as_ref().err().map(ToString::to_string);
                finish(sample, &record, result.ok(), error).await;
            });
            return blocked();
        }
        if codings.is_some() {
            for name in [
                "content-length",
                "etag",
                "content-md5",
                "digest",
                "content-digest",
                "repr-digest",
                "accept-ranges",
            ] {
                parts.headers.remove(name);
            }
        }

        let (input, reader) = tokio::io::duplex(8192);
        let (writer, output) = tokio::io::duplex(8192);
        let (send, completion) = oneshot::channel();
        tokio::spawn(async move {
            let mut sample = Self::sample(directory, &record, original).await;
            let incoming = receive(body, Some(input), &mut sample, &record);
            let outgoing = async {
                if let Some(codings) = codings {
                    html::rewrite(
                        reader,
                        writer,
                        codings,
                        media.expect("HTML content type"),
                        &rules,
                        &record,
                    )
                    .await
                } else {
                    let mut reader = reader;
                    let mut writer = writer;
                    tokio::io::copy(&mut reader, &mut writer).await?;
                    writer.shutdown().await?;
                    Ok(())
                }
            };
            let (incoming, outgoing) = tokio::join!(incoming, outgoing);
            let trailers = sample
                .as_ref()
                .and_then(|_| incoming.as_ref().ok().cloned());
            let error = outgoing
                .as_ref()
                .err()
                .or_else(|| incoming.as_ref().err())
                .map(ToString::to_string);
            let result = incoming.and_then(|mut trailers| {
                outgoing?;
                if filtering {
                    for name in [
                        "etag",
                        "content-md5",
                        "digest",
                        "content-digest",
                        "repr-digest",
                    ] {
                        trailers.remove(name);
                    }
                }
                Ok(trailers)
            });
            let _ = send.send(result);
            finish(sample, &record, trailers, error).await;
        });
        let data = ReaderStream::new(output)
            .map_ok(Frame::data)
            .map_err(anyhow::Error::from);
        let tail = stream::once(async move {
            let trailers = completion
                .await
                .context("response processing task ended")??;
            Ok::<_, anyhow::Error>((!trailers.is_empty()).then(|| Frame::trailers(trailers)))
        })
        .try_filter_map(futures_util::future::ok);
        let body = StreamBody::new(data.chain(tail)).boxed_unsync();
        Response::from_parts(parts, body)
    }

    async fn sample(
        directory: Option<PathBuf>,
        record: &Arc<Record>,
        response: Option<http::response::Parts>,
    ) -> Option<Sample> {
        let directory = directory?;
        match Sample::new(&directory, record, response).await {
            Ok(sample) => Some(sample),
            Err(error) => {
                warn!(path = %directory.display(), ?error, "failed to create probe sample");
                None
            }
        }
    }
}

fn blocked() -> Response<ResponseBody> {
    let mut response = Response::new(body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn match_url(uri: &str, rules: &[Arc<Rule>], record: &Record) -> bool {
    let mut matched = false;
    for rule in rules {
        if rule.urls.is_match(uri) {
            record.hit(&rule.name, "url");
            matched = true;
        }
    }
    matched
}

fn cookies(headers: &mut HeaderMap, header: HeaderName, rules: &[Arc<Rule>], record: &Record) {
    let mut values = Vec::new();
    let mut changed = false;
    for value in headers.get_all(&header) {
        let mut retained = Vec::new();
        let entries: Vec<_> = if header == COOKIE {
            value.as_bytes().split(|&byte| byte == b';').collect()
        } else {
            vec![value.as_bytes()]
        };
        for entry in entries {
            let mut remove = false;
            if let Some(end) = entry.iter().position(|&byte| byte == b'=')
                && let Ok(name) = std::str::from_utf8(entry[..end].trim_ascii())
            {
                for rule in rules {
                    if rule.cookies.is_match(name) {
                        record.hit(
                            &rule.name,
                            if header == COOKIE {
                                "request-cookie"
                            } else {
                                "response-cookie"
                            },
                        );
                        remove = true;
                    }
                }
            }
            if remove {
                changed = true;
            } else {
                retained.push(entry);
            }
        }
        if !retained.is_empty() {
            values.push(
                HeaderValue::from_bytes(&retained.join(&b';')).expect("retained cookie bytes"),
            );
        }
    }
    if changed {
        headers.remove(&header);
        for value in values {
            headers.append(header.clone(), value);
        }
    }
}

async fn receive(
    mut body: Incoming,
    mut output: Option<DuplexStream>,
    sample: &mut Option<Sample>,
    record: &Record,
) -> Result<HeaderMap> {
    let mut trailers = HeaderMap::new();
    while let Some(frame) = body.frame().await {
        match frame?.into_data() {
            Ok(data) => {
                let (written, saved) = tokio::join!(
                    async {
                        match output.as_mut() {
                            Some(writer) => writer.write_all(&data).await,
                            None => Ok(()),
                        }
                    },
                    async {
                        match sample.as_mut() {
                            Some(capture) => capture.write(&data).await,
                            None => Ok(()),
                        }
                    },
                );
                if let Err(error) = saved {
                    warn!(uri = %record.uri, ?error, "failed to write probe sample");
                    *sample = None;
                }
                if let Err(error) = written {
                    output = None;
                    if sample.is_none() || !record.matched() {
                        return Err(error.into());
                    }
                }
            }
            Err(frame) => {
                if let Ok(headers) = frame.into_trailers() {
                    trailers.extend(headers);
                }
            }
        }
    }
    Ok(trailers)
}

async fn finish(
    sample: Option<Sample>,
    record: &Record,
    trailers: Option<HeaderMap>,
    error: Option<String>,
) {
    if let Some(sample) = sample
        && let Err(error) = sample.finish(trailers.is_some(), trailers, error).await
    {
        warn!(uri = %record.uri, ?error, "failed to save probe sample");
    }
}
