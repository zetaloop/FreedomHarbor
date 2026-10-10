use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use futures_util::{StreamExt, TryStreamExt, stream};
use http::{
    HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode,
    header::{CACHE_CONTROL, CONTENT_RANGE, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE},
};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body as _, Frame, Incoming};
use lol_html::Selector;
use regex::{Regex, RegexSet};
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    sync::oneshot,
};
use tokio_util::io::ReaderStream;
use tracing::warn;
use url::Url;

use crate::{
    body::{self, ResponseBody},
    config, html,
    sample::{Record, Sample},
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

    pub async fn block(&self, body: Incoming, exchange: &Exchange) -> Response<ResponseBody> {
        let sample = self.sample(&exchange.record, None).await;
        let record = Arc::clone(&exchange.record);
        tokio::spawn(async move {
            let mut sample = sample;
            let result = receive(body, None, &mut sample, &record).await;
            finish(sample, &record, &result, None).await;
        });
        blocked()
    }

    pub async fn response(
        &self,
        response: Response<Incoming>,
        exchange: Exchange,
    ) -> Result<Response<ResponseBody>> {
        let (mut parts, body) = response.into_parts();
        let original = parts.clone();
        let Exchange { record, rules, .. } = exchange;
        cookies(&mut parts.headers, SET_COOKIE, &rules, &record);
        let redirect = parts
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
            return Ok(Response::from_parts(
                parts,
                body.map_err(anyhow::Error::from).boxed_unsync(),
            ));
        }
        let sample = self.sample(&record, Some(&original)).await;
        if redirect {
            tokio::spawn(async move {
                let mut sample = sample;
                let result = receive(body, None, &mut sample, &record).await;
                finish(sample, &record, &result, None).await;
            });
            return Ok(blocked());
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
            let mut sample = sample;
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
            let error = outgoing.as_ref().err().map(ToString::to_string);
            finish(sample, &record, &incoming, error).await;
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
        Ok(Response::from_parts(parts, body))
    }

    async fn sample(
        &self,
        record: &Arc<Record>,
        response: Option<&http::response::Parts>,
    ) -> Option<Sample> {
        let directory = self.samples.as_ref()?;
        match Sample::new(directory, record, response).await {
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
                if let Some(capture) = sample.as_mut()
                    && let Err(error) = capture.write(&data).await
                {
                    warn!(uri = %record.uri, ?error, "failed to write probe sample");
                    *sample = None;
                }
                if let Some(writer) = output.as_mut()
                    && let Err(error) = writer.write_all(&data).await
                {
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
    incoming: &Result<HeaderMap>,
    error: Option<String>,
) {
    if let Some(sample) = sample {
        let error = error.or_else(|| incoming.as_ref().err().map(ToString::to_string));
        if let Err(error) = sample
            .finish(incoming.is_ok(), incoming.as_ref().ok(), error)
            .await
        {
            warn!(uri = %record.uri, ?error, "failed to save probe sample");
        }
    }
}
