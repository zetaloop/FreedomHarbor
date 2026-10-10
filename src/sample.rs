use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use anyhow::Result;
use http::{HeaderMap, Method, Request, Version};
use serde::Serialize;
use tempfile::TempDir;
use tokio::{fs, io::AsyncWriteExt};
use tracing::{info, warn};

#[derive(Serialize)]
pub struct Hit {
    pub rule: String,
    pub action: &'static str,
}

pub struct Record {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub uri: String,
    method: Method,
    version: Version,
    headers: HeaderMap,
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
        let mut hits = self.hits.lock().expect("sample lock poisoned");
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
        !self.hits.lock().expect("sample lock poisoned").is_empty()
    }

    fn metadata(&self, complete: bool, error: Option<String>) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(&serde_json::json!({
            "time": self.time,
            "source": self.source,
            "destination": self.destination,
            "uri": self.uri,
            "hits": *self.hits.lock().expect("sample lock poisoned"),
            "complete": complete,
            "error": error,
        }))?)
    }
}

pub struct Sample {
    directory: Option<TempDir>,
    body: fs::File,
    record: Arc<Record>,
}

impl Sample {
    pub async fn new(
        directory: &Path,
        record: &Arc<Record>,
        response: Option<&http::response::Parts>,
    ) -> Result<Self> {
        fs::create_dir_all(directory).await?;
        let directory = tempfile::Builder::new()
            .prefix("event-")
            .tempdir_in(directory)?;
        let request = format!("{} {} {:?}\r\n", record.method, record.uri, record.version);
        fs::write(
            directory.path().join("request.headers"),
            headers(&request, &record.headers),
        )
        .await?;
        let name = if let Some(response) = response {
            let status = format!("{:?} {}\r\n", response.version, response.status);
            fs::write(
                directory.path().join("response.headers"),
                headers(&status, &response.headers),
            )
            .await?;
            "response.body"
        } else {
            "request.body"
        };
        let body = fs::File::create(directory.path().join(name)).await?;
        Ok(Self {
            directory: Some(directory),
            body,
            record: Arc::clone(record),
        })
    }

    pub async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.body.write_all(bytes).await?;
        Ok(())
    }

    pub async fn finish(
        mut self,
        complete: bool,
        trailers: Option<&HeaderMap>,
        error: Option<String>,
    ) -> Result<()> {
        if !self.record.matched() {
            return Ok(());
        }
        self.body.flush().await?;
        let directory = self.directory.as_ref().expect("sample directory").path();
        if let Some(trailers) = trailers
            && !trailers.is_empty()
        {
            fs::write(directory.join("trailers.headers"), headers("", trailers)).await?;
        }
        let metadata = self.record.metadata(complete, error)?;
        fs::write(directory.join("event.json"), metadata).await?;
        let directory = self.directory.take().expect("sample directory").keep();
        info!(path = %directory.display(), "probe sample saved");
        Ok(())
    }
}

impl Drop for Sample {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take()
            && self.record.matched()
        {
            let directory = directory.keep();
            let result = self
                .record
                .metadata(false, Some("processing interrupted".into()))
                .and_then(|metadata| {
                    std::fs::write(directory.join("event.json"), metadata)?;
                    Ok(())
                });
            if let Err(error) = result {
                warn!(path = %directory.display(), ?error, "failed to describe interrupted probe sample");
            }
            info!(path = %directory.display(), "partial probe sample saved");
        }
    }
}

fn headers(first: &str, headers: &HeaderMap) -> Vec<u8> {
    let mut bytes = first.as_bytes().to_vec();
    for (name, value) in headers {
        bytes.extend_from_slice(name.as_str().as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    bytes
}
