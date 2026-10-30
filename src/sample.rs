use std::{path::Path, sync::Arc};

use anyhow::Result;
use http::HeaderMap;
use tempfile::TempDir;
use tokio::{fs, io::AsyncWriteExt};
use tracing::{info, warn};

use crate::probe::Record;

pub struct Sample {
    directory: Option<TempDir>,
    body: fs::File,
    record: Arc<Record>,
    response: Option<http::response::Parts>,
}

impl Sample {
    pub async fn new(
        directory: &Path,
        record: &Arc<Record>,
        response: Option<http::response::Parts>,
    ) -> Result<Self> {
        let name = if response.is_some() {
            "response.body"
        } else {
            "request.body"
        };
        let directory = directory.to_owned();
        let (directory, body) = tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&directory)?;
            let directory = tempfile::Builder::new()
                .prefix("event-")
                .tempdir_in(directory)?;
            let body = std::fs::File::create(directory.path().join(name))?;
            Ok::<_, std::io::Error>((directory, body))
        })
        .await??;
        Ok(Self {
            directory: Some(directory),
            body: fs::File::from_std(body),
            record: Arc::clone(record),
            response,
        })
    }

    pub async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.body.write_all(bytes).await?;
        Ok(())
    }

    pub async fn finish(
        mut self,
        complete: bool,
        trailers: Option<HeaderMap>,
        error: Option<String>,
    ) -> Result<()> {
        if !self.record.matched() {
            return Ok(());
        }
        self.body.flush().await?;
        tokio::task::spawn_blocking(move || {
            let directory = self.directory.as_ref().expect("sample directory").path();
            self.describe(directory, complete, trailers.as_ref(), error)?;
            let directory = self.directory.take().expect("sample directory").keep();
            info!(path = %directory.display(), "probe sample saved");
            Ok(())
        })
        .await?
    }

    fn describe(
        &self,
        directory: &Path,
        complete: bool,
        trailers: Option<&HeaderMap>,
        error: Option<String>,
    ) -> Result<()> {
        let request = format!(
            "{} {} {:?}\r\n",
            self.record.method, self.record.uri, self.record.version
        );
        std::fs::write(
            directory.join("request.headers"),
            headers(&request, &self.record.headers),
        )?;
        if let Some(response) = &self.response {
            let status = format!("{:?} {}\r\n", response.version, response.status);
            std::fs::write(
                directory.join("response.headers"),
                headers(&status, &response.headers),
            )?;
        }
        if let Some(trailers) = trailers
            && !trailers.is_empty()
        {
            std::fs::write(directory.join("trailers.headers"), headers("", trailers))?;
        }
        let metadata = self.record.metadata(complete, error)?;
        std::fs::write(directory.join("event.json"), metadata)?;
        Ok(())
    }
}

impl Drop for Sample {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take()
            && self.record.matched()
        {
            let directory = directory.keep();
            if let Err(error) = self.describe(
                &directory,
                false,
                None,
                Some("processing interrupted".into()),
            ) {
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
