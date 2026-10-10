use std::{
    borrow::Cow,
    pin::Pin,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use async_compression::tokio::{bufread, write};
use http::{HeaderMap, header::CONTENT_ENCODING};
use lol_html::{
    AsciiCompatibleEncoding,
    send::{Element, ElementContentHandlers, HtmlRewriter, Settings},
    text,
};
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream};
use tracing::debug;

use crate::{probe::Rule, sample::Record};

pub enum Coding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

type Reader = Pin<Box<dyn AsyncBufRead + Send>>;
type Writer = Pin<Box<dyn AsyncWrite + Send>>;

pub fn encoding(media: &mime::Mime) -> Option<AsciiCompatibleEncoding> {
    match media.get_param(mime::CHARSET) {
        Some(charset) => encoding_rs::Encoding::for_label(charset.as_str().as_bytes())
            .and_then(AsciiCompatibleEncoding::new),
        None => Some(AsciiCompatibleEncoding::utf_8()),
    }
}

pub fn codings(headers: &HeaderMap) -> Option<Vec<Coding>> {
    let mut result = Vec::new();
    for value in headers.get_all(CONTENT_ENCODING) {
        for coding in value.to_str().ok()?.split(',').map(str::trim) {
            result.push(match coding.to_ascii_lowercase().as_str() {
                "gzip" | "x-gzip" => Coding::Gzip,
                "deflate" => Coding::Deflate,
                "br" => Coding::Brotli,
                "zstd" => Coding::Zstd,
                "identity" => continue,
                _ => {
                    debug!(coding, "unrecognized HTML content encoding");
                    return None;
                }
            });
        }
    }
    Some(result)
}

pub async fn rewrite(
    input: DuplexStream,
    output: DuplexStream,
    codings: Vec<Coding>,
    media: mime::Mime,
    rules: &[Arc<Rule>],
    record: &Record,
) -> Result<()> {
    let mut reader: Reader = Box::pin(BufReader::new(input));
    let mut writer: Writer = Box::pin(output);
    for coding in codings.iter().rev() {
        reader = match coding {
            Coding::Gzip => {
                let mut decoder = bufread::GzipDecoder::new(reader);
                decoder.multiple_members(true);
                Box::pin(BufReader::new(decoder))
            }
            Coding::Deflate => Box::pin(BufReader::new(bufread::ZlibDecoder::new(reader))),
            Coding::Brotli => Box::pin(BufReader::new(bufread::BrotliDecoder::new(reader))),
            Coding::Zstd => {
                let mut decoder = bufread::ZstdDecoder::new(reader);
                decoder.multiple_members(true);
                Box::pin(BufReader::new(decoder))
            }
        };
        writer = match coding {
            Coding::Gzip => Box::pin(write::GzipEncoder::new(writer)),
            Coding::Deflate => Box::pin(write::ZlibEncoder::new(writer)),
            Coding::Brotli => Box::pin(write::BrotliEncoder::new(writer)),
            Coding::Zstd => Box::pin(write::ZstdEncoder::new(writer)),
        };
    }
    let mut settings = Settings::new_send()
        .with_encoding(encoding(&media).context("unsupported HTML charset")?)
        .with_adjust_charset_on_meta_tag(media.get_param(mime::CHARSET).is_none());
    for rule in rules {
        for selector in &rule.elements {
            settings = settings.append_element_content_handler((
                Cow::Borrowed(selector),
                ElementContentHandlers::default().element(move |element: &mut Element| {
                    record.hit(&rule.name, "element");
                    element.remove();
                    Ok(())
                }),
            ));
        }
    }
    if rules.iter().any(|rule| !rule.scripts.is_empty()) {
        let mut script = String::new();
        settings =
            settings.append_element_content_handler(text!("script:not([src])", move |text| {
                script.push_str(text.as_str());
                if text.last_in_text_node() {
                    let mut removed = false;
                    for rule in rules {
                        if rule.scripts.is_match(&script) {
                            record.hit(&rule.name, "script");
                            removed = true;
                        }
                    }
                    if removed {
                        text.remove();
                        script.clear();
                    } else {
                        text.set_str(std::mem::take(&mut script));
                    }
                } else {
                    text.remove();
                }
                Ok(())
            }));
    }
    let pending = Mutex::new(Vec::new());
    let mut rewriter = HtmlRewriter::new(settings, |bytes: &[u8]| {
        pending
            .lock()
            .expect("HTML output lock poisoned")
            .extend_from_slice(bytes);
    });
    let mut input = [0; 8192];
    let mut output = Vec::new();
    loop {
        let count = reader.read(&mut input).await?;
        if count == 0 {
            break;
        }
        rewriter.write(&input[..count])?;
        flush(&pending, &mut output, &mut writer).await?;
    }
    rewriter.end()?;
    flush(&pending, &mut output, &mut writer).await?;
    writer.shutdown().await?;
    Ok(())
}

async fn flush(pending: &Mutex<Vec<u8>>, output: &mut Vec<u8>, writer: &mut Writer) -> Result<()> {
    std::mem::swap(
        output,
        &mut pending.lock().expect("HTML output lock poisoned"),
    );
    if !output.is_empty() {
        writer.write_all(output).await?;
        writer.flush().await?;
        output.clear();
    }
    Ok(())
}
