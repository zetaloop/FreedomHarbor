use std::{
    future::poll_fn,
    io::{self, Cursor},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use anyhow::{Context as _, Result};
use futures_util::TryFutureExt;
use hyper::body::Bytes;
use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, BufReader, Chain,
        ReadBuf,
    },
    net::{
        TcpStream,
        tcp::{ReadHalf, WriteHalf},
    },
    sync::oneshot,
};
use tracing::debug;

use crate::{
    protocol::Parse,
    tcp::{self, Prefix},
    tls::Records,
};

const XMPP: &str = "http://etherx.jabber.org/streams";
const TLS: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const LDAP: &[u8] = b"1.3.6.1.4.1.1466.20037";
const SSL_REQUEST: u32 = 80877103;
const GSS_REQUEST: u32 = 80877104;

#[derive(Clone, Copy)]
pub enum Protocol {
    Numeric,
    Pop,
    Imap,
    Xml,
    Ldap,
    Postgres,
    Mysql,
}

enum Pending {
    Code(u16),
    Pop,
    Tag(Vec<u8>),
    Xml,
    Ldap(u32),
    Postgres,
}

#[derive(Default)]
struct State {
    pending: Option<Pending>,
    ready: bool,
    done: bool,
    data: bool,
    data_pending: bool,
    literal: Option<(Vec<u8>, oneshot::Sender<bool>)>,
}

impl State {
    fn request(&mut self, pending: Pending) {
        self.pending = Some(pending);
        self.ready = false;
    }

    fn finish(&mut self) {
        *self = Self {
            done: true,
            ..Self::default()
        };
    }
}

struct Stream<'a> {
    reader: BufReader<Chain<Cursor<Vec<u8>>, ReadHalf<'a>>>,
    writer: WriteHalf<'a>,
    pending: Vec<u8>,
    sent: usize,
    skip: usize,
    read: u64,
    written: u64,
}

impl<'a> Stream<'a> {
    fn new(reader: ReadHalf<'a>, writer: WriteHalf<'a>, prefix: Prefix) -> Self {
        Self {
            reader: BufReader::new(Cursor::new(prefix.data).chain(reader)),
            writer,
            pending: Vec::new(),
            sent: 0,
            skip: prefix.sent,
            read: 0,
            written: 0,
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.pending.len() {
            let count =
                ready!(Pin::new(&mut self.writer).poll_write(cx, &self.pending[self.sent..]))
                    .map_err(|error| {
                        io::Error::new(error.kind(), anyhow::Error::new(error).context("write"))
                    })?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += count;
            self.written += count as u64;
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }

    async fn flush(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_flush(cx)).await
    }

    async fn line(&mut self, output: &mut Vec<u8>) -> io::Result<()> {
        output.clear();
        self.read_until(b'\n', output).await?;
        Ok(())
    }

    async fn copy(&mut self, mut count: u64) -> io::Result<()> {
        while count != 0 {
            let data = self.fill_buf().await?;
            if data.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let length = count.min(data.len() as u64) as usize;
            self.consume(length);
            count -= length as u64;
        }
        Ok(())
    }

    async fn dot(&mut self) -> io::Result<()> {
        let mut position = 0;
        let mut dot = true;
        loop {
            let data = self.fill_buf().await?;
            if data.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let length = data
                .iter()
                .position(|&byte| byte == b'\n')
                .map_or(data.len(), |index| index + 1);
            let ended = data[length - 1] == b'\n';
            if dot {
                dot = b".\r\n".get(position..position + length) == Some(&data[..length]);
                position += length;
            }
            self.consume(length);
            if ended {
                if dot && position == 3 {
                    return Ok(());
                }
                position = 0;
                dot = true;
            }
        }
    }

    async fn parts(mut self) -> io::Result<(ReadHalf<'a>, WriteHalf<'a>, Vec<u8>, u64)> {
        self.flush().await?;
        let mut prefix = self.reader.buffer().to_vec();
        let (cursor, reader) = self.reader.into_inner().into_inner();
        prefix.extend_from_slice(&cursor.get_ref()[cursor.position() as usize..]);
        prefix.drain(..self.skip);
        Ok((reader, self.writer, prefix, self.written))
    }

    async fn finish(self) -> Result<u64> {
        let (reader, writer, prefix, written) = self.parts().await?;
        Ok(written + tcp::transfer(reader, writer, Bytes::from(prefix)).await?)
    }

    async fn handshake(self) -> Result<u64> {
        let (mut reader, writer, mut data, written) = self.parts().await?;
        let mut buffer = [0; 8192];
        loop {
            match Records::parse(&data) {
                Ok(hello) if hello.hello.ready => {
                    hello.fragment(&mut data);
                    debug!("TLS upgrade detected");
                    break;
                }
                Err(Parse::Invalid) => break,
                _ => {}
            }
            let count = reader.read(&mut buffer).await.context("read")?;
            if count == 0 {
                break;
            }
            data.extend_from_slice(&buffer[..count]);
        }
        Ok(written + tcp::transfer(reader, writer, Bytes::from(data)).await?)
    }
}

impl AsyncBufRead for Stream<'_> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        ready!(this.poll_flush(cx))?;
        Pin::new(&mut this.reader)
            .poll_fill_buf(cx)
            .map_err(|error| {
                io::Error::new(error.kind(), anyhow::Error::new(error).context("read"))
            })
    }

    fn consume(self: Pin<&mut Self>, count: usize) {
        let this = self.get_mut();
        let skipped = count.min(this.skip);
        this.skip -= skipped;
        this.pending
            .extend_from_slice(&this.reader.buffer()[skipped..count]);
        this.reader.consume(count);
        this.read += count as u64;
    }
}

impl AsyncRead for Stream<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let data = ready!(self.as_mut().poll_fill_buf(cx))?;
        let count = data.len().min(output.remaining());
        output.put_slice(&data[..count]);
        self.consume(count);
        Poll::Ready(Ok(()))
    }
}

pub fn detect(request: &[u8], response: &[u8]) -> Result<Option<Protocol>, Parse> {
    if request.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'<')
        || response.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'<')
    {
        return Ok(Some(Protocol::Xml));
    }
    if request.first() == Some(&0x30) {
        let Some((_, start)) = length(request, 1) else {
            return Err(Parse::Incomplete);
        };
        return match request.get(start) {
            Some(2) => Ok(Some(Protocol::Ldap)),
            Some(_) => Ok(None),
            None => Err(Parse::Incomplete),
        };
    }
    for value in [SSL_REQUEST, GSS_REQUEST] {
        let mut header = [0, 0, 0, 8, 0, 0, 0, 0];
        header[4..].copy_from_slice(&value.to_be_bytes());
        if request.starts_with(&header) {
            return Ok(Some(Protocol::Postgres));
        }
        if !request.is_empty() && header.starts_with(request) {
            return Err(Parse::Incomplete);
        }
    }
    if !request.is_empty() && response.is_empty() {
        return Ok(None);
    }
    for (prefix, protocol) in [
        (b"220".as_slice(), Protocol::Numeric),
        (b"+OK".as_slice(), Protocol::Pop),
        (b"* OK".as_slice(), Protocol::Imap),
        (b"* PREAUTH".as_slice(), Protocol::Imap),
    ] {
        if response.len() >= prefix.len() && response[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return Ok(Some(protocol));
        }
        if prefix[..response.len().min(prefix.len())].eq_ignore_ascii_case(response) {
            return Err(Parse::Incomplete);
        }
    }
    if response.len() < 5 {
        return Err(Parse::Incomplete);
    }
    Ok((response[3] == 0 && response[4] == 10).then_some(Protocol::Mysql))
}

pub async fn forward(
    protocol: Protocol,
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    request: Prefix,
    response: Prefix,
) -> Result<(u64, u64)> {
    let (client_read, client_write) = client.split();
    let (upstream_read, upstream_write) = upstream.split();
    let state = Arc::new(Mutex::new(State::default()));
    let request = Stream::new(client_read, upstream_write, request);
    let response = Stream::new(upstream_read, client_write, response);
    tokio::try_join!(
        inspect(request, protocol, Arc::clone(&state), true)
            .map_err(|error| error.context("client to upstream")),
        inspect(response, protocol, state, false)
            .map_err(|error| error.context("upstream to client")),
    )
}

async fn inspect(
    mut stream: Stream<'_>,
    protocol: Protocol,
    state: Arc<Mutex<State>>,
    client: bool,
) -> Result<u64> {
    if matches!(protocol, Protocol::Xml) {
        return xml(stream, state, client).await;
    }
    if matches!(protocol, Protocol::Mysql) && !client {
        return stream.finish().await;
    }
    let mut line = Vec::new();
    let mut tag = Vec::new();
    loop {
        let data = stream.fill_buf().await?;
        if data.is_empty() {
            state.lock().expect("upgrade lock poisoned").finish();
            break;
        }
        let (done, ready) = {
            let state = state.lock().expect("upgrade lock poisoned");
            (state.done, state.ready)
        };
        if done {
            break;
        }
        if client && ready && matches!(data[0], 20 | 22) {
            state.lock().expect("upgrade lock poisoned").finish();
            drop(line);
            drop(tag);
            drop(state);
            return stream.handshake().await;
        }
        if client && tag.is_empty() {
            let mut state = state.lock().expect("upgrade lock poisoned");
            state.pending = None;
            state.ready = false;
            state.data_pending = false;
        }
        let result: Result<()> = async {
            match protocol {
                Protocol::Ldap => {
                    ldap(&mut stream, &state, client).await?;
                }
                Protocol::Postgres => {
                    postgres(&mut stream, &state, client).await?;
                }
                Protocol::Mysql => {
                    mysql(&mut stream, &state).await?;
                }
                Protocol::Numeric | Protocol::Pop | Protocol::Imap => {
                    if client && state.lock().expect("upgrade lock poisoned").data {
                        stream.dot().await?;
                        state.lock().expect("upgrade lock poisoned").data = false;
                        return Ok(());
                    }
                    stream.line(&mut line).await?;
                    let value = line.trim_ascii();
                    if client {
                        let mut words = value
                            .split(u8::is_ascii_whitespace)
                            .filter(|word| !word.is_empty());
                        let first = words.next().unwrap_or_default();
                        let second = words.next().unwrap_or_default();
                        let third = words.next().unwrap_or_default();
                        if matches!(protocol, Protocol::Imap) {
                            if tag.is_empty() {
                                tag.extend_from_slice(first);
                                if second.eq_ignore_ascii_case(b"STARTTLS") && third.is_empty() {
                                    state
                                        .lock()
                                        .expect("upgrade lock poisoned")
                                        .request(Pending::Tag(tag.clone()));
                                }
                            }
                            if let Some((count, asynchronous)) = literal(value) {
                                let receive = if asynchronous {
                                    None
                                } else {
                                    let (send, receive) = oneshot::channel();
                                    state.lock().expect("upgrade lock poisoned").literal =
                                        Some((tag.clone(), send));
                                    Some(receive)
                                };
                                stream.flush().await?;
                                if match receive {
                                    Some(receive) => receive.await.unwrap_or(false),
                                    None => true,
                                } {
                                    stream.copy(count).await?;
                                } else {
                                    tag.clear();
                                }
                            } else {
                                tag.clear();
                            }
                        } else if first.eq_ignore_ascii_case(b"STARTTLS") && second.is_empty() {
                            state
                                .lock()
                                .expect("upgrade lock poisoned")
                                .request(Pending::Code(220));
                        } else if first.eq_ignore_ascii_case(b"AUTH")
                            && second.eq_ignore_ascii_case(b"TLS")
                            && third.is_empty()
                        {
                            state
                                .lock()
                                .expect("upgrade lock poisoned")
                                .request(Pending::Code(234));
                        } else if matches!(protocol, Protocol::Pop)
                            && first.eq_ignore_ascii_case(b"STLS")
                            && second.is_empty()
                        {
                            state
                                .lock()
                                .expect("upgrade lock poisoned")
                                .request(Pending::Pop);
                        } else if first.eq_ignore_ascii_case(b"DATA") && second.is_empty() {
                            state.lock().expect("upgrade lock poisoned").data_pending = true;
                        } else if first.eq_ignore_ascii_case(b"BDAT")
                            && let Some(count) = number(second)
                        {
                            stream.copy(count).await?;
                        }
                    } else {
                        let data = response(value, &state);
                        if matches!(protocol, Protocol::Imap)
                            && data
                            && let Some((count, _)) = literal(value)
                        {
                            stream.copy(count).await?;
                        }
                    }
                }
                Protocol::Xml => unreachable!("XML reader"),
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::UnexpectedEof)
            {
                debug!(?error, "TLS upgrade recognition ended");
                let mut state = state.lock().expect("upgrade lock poisoned");
                state.finish();
                break;
            }
            return Err(error);
        }
        stream.flush().await?;
    }
    drop(line);
    drop(tag);
    drop(state);
    stream.finish().await
}

fn response(line: &[u8], state: &Mutex<State>) -> bool {
    let mut state = state.lock().expect("upgrade lock poisoned");
    let mut words = line
        .split(u8::is_ascii_whitespace)
        .filter(|word| !word.is_empty());
    let first = words.next().unwrap_or_default();
    let second = words.next().unwrap_or_default();
    if state.literal.as_ref().is_some_and(|(tag, _)| {
        first == b"+"
            || (first == tag
                && (second.eq_ignore_ascii_case(b"NO") || second.eq_ignore_ascii_case(b"BAD")))
    }) && let Some((_, send)) = state.literal.take()
    {
        let _ = send.send(first == b"+");
    }
    if state.data_pending && first == b"354" {
        state.data = true;
        state.data_pending = false;
    }
    let ready = match &state.pending {
        Some(Pending::Code(code)) if first.len() == 3 => {
            number(first).map(|value| value == u64::from(*code))
        }
        Some(Pending::Pop) if first.eq_ignore_ascii_case(b"+OK") => Some(true),
        Some(Pending::Pop) if first.eq_ignore_ascii_case(b"-ERR") => Some(false),
        Some(Pending::Tag(tag)) if first == tag => Some(second.eq_ignore_ascii_case(b"OK")),
        _ => None,
    };
    if let Some(ready) = ready {
        state.ready = ready;
    }
    first == b"*"
        && ![b"OK".as_slice(), b"NO", b"BAD", b"BYE", b"PREAUTH"]
            .iter()
            .any(|status| second.eq_ignore_ascii_case(status))
}

async fn xml(stream: Stream<'_>, state: Arc<Mutex<State>>, client: bool) -> Result<u64> {
    let mut reader = NsReader::from_reader(stream);
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let mut opening = false;
    loop {
        let data = reader.get_mut().fill_buf().await?;
        if data.is_empty() {
            state.lock().expect("upgrade lock poisoned").finish();
            break;
        }
        let (done, ready) = {
            let state = state.lock().expect("upgrade lock poisoned");
            (state.done, state.ready)
        };
        if done {
            break;
        }
        if client && ready && matches!(data[0], 20 | 22) {
            state.lock().expect("upgrade lock poisoned").finish();
            drop(buffer);
            drop(state);
            return reader.into_inner().handshake().await;
        }
        buffer.clear();
        let event = reader.read_resolved_event_into_async(&mut buffer).await;
        let (namespace, event) = match event {
            Ok(event) => event,
            Err(error @ quick_xml::Error::Io(_)) => return Err(error.into()),
            Err(error) => {
                debug!(?error, "XML upgrade recognition ended");
                state.lock().expect("upgrade lock poisoned").finish();
                break;
            }
        };
        let namespace = match &namespace {
            ResolveResult::Bound(namespace) => namespace.as_ref(),
            _ => "",
        };
        match event {
            Event::Start(element) => {
                if depth == 0 && (namespace != XMPP || element.local_name().as_ref() != "stream") {
                    state.lock().expect("upgrade lock poisoned").finish();
                }
                opening = depth == 1 && namespace == TLS;
                if opening && client && element.local_name().as_ref() != "starttls" {
                    opening = false;
                }
                depth += 1;
            }
            Event::Empty(element) if depth == 1 && namespace == TLS => {
                let mut state = state.lock().expect("upgrade lock poisoned");
                if client && element.local_name().as_ref() == "starttls" {
                    state.request(Pending::Xml);
                } else if !client && matches!(state.pending, Some(Pending::Xml)) {
                    state.ready = element.local_name().as_ref() == "proceed";
                }
            }
            Event::End(element) => {
                depth = depth.saturating_sub(1);
                if opening && depth == 1 && namespace == TLS {
                    let mut state = state.lock().expect("upgrade lock poisoned");
                    if client && element.local_name().as_ref() == "starttls" {
                        state.request(Pending::Xml);
                    } else if !client && matches!(state.pending, Some(Pending::Xml)) {
                        state.ready = element.local_name().as_ref() == "proceed";
                    }
                }
                opening = false;
            }
            Event::Eof => break,
            _ => {}
        }
        reader.get_mut().flush().await?;
    }
    state.lock().expect("upgrade lock poisoned").finish();
    drop(buffer);
    drop(state);
    reader.into_inner().finish().await
}

async fn postgres(stream: &mut Stream<'_>, state: &Mutex<State>, client: bool) -> Result<()> {
    if client {
        let length = stream.read_u32().await?;
        if length == 8 {
            let code = stream.read_u32().await?;
            if matches!(code, SSL_REQUEST | GSS_REQUEST) {
                state
                    .lock()
                    .expect("upgrade lock poisoned")
                    .request(Pending::Postgres);
                return Ok(());
            }
        }
        state.lock().expect("upgrade lock poisoned").finish();
    } else {
        let reply = stream.read_u8().await?;
        let mut state = state.lock().expect("upgrade lock poisoned");
        if matches!(state.pending, Some(Pending::Postgres)) {
            state.ready = reply == b'S';
            if !matches!(reply, b'S' | b'N') {
                state.finish();
            }
        }
    }
    Ok(())
}

async fn mysql(stream: &mut Stream<'_>, state: &Mutex<State>) -> Result<()> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[..3] == [32, 0, 0] {
        let mut data = [0; 32];
        stream.read_exact(&mut data).await?;
        if u32::from_le_bytes(data[..4].try_into()?) & 0x800 != 0 {
            state.lock().expect("upgrade lock poisoned").ready = true;
            return Ok(());
        }
    }
    state.lock().expect("upgrade lock poisoned").finish();
    Ok(())
}

async fn ldap(stream: &mut Stream<'_>, state: &Mutex<State>, client: bool) -> Result<()> {
    let Some((0x30, size)) = field(stream).await? else {
        state.lock().expect("upgrade lock poisoned").finish();
        return Ok(());
    };
    let Some(end) = stream.read.checked_add(size) else {
        state.lock().expect("upgrade lock poisoned").finish();
        return Ok(());
    };
    let Some(id) = integer(stream, 2, end).await? else {
        state.lock().expect("upgrade lock poisoned").finish();
        return Ok(());
    };
    let Some((kind, size)) = field(stream).await? else {
        state.lock().expect("upgrade lock poisoned").finish();
        return Ok(());
    };
    let Some(operation) = stream.read.checked_add(size).filter(|&value| value <= end) else {
        state.lock().expect("upgrade lock poisoned").finish();
        return Ok(());
    };
    if client && kind == 0x77 {
        if let Some((0x80, size)) = field(stream).await?
            && size == LDAP.len() as u64
            && stream.read + size <= operation
        {
            let mut name = [0; LDAP.len()];
            stream.read_exact(&mut name).await?;
            if name == LDAP {
                state
                    .lock()
                    .expect("upgrade lock poisoned")
                    .request(Pending::Ldap(id));
            }
        }
    } else if !client && kind == 0x78 {
        let result = integer(stream, 10, operation).await?;
        let mut state = state.lock().expect("upgrade lock poisoned");
        if matches!(state.pending, Some(Pending::Ldap(pending)) if pending == id) {
            state.ready = result == Some(0);
        }
    }
    if stream.read <= end {
        stream.copy(end - stream.read).await?;
    } else {
        state.lock().expect("upgrade lock poisoned").finish();
    }
    Ok(())
}

async fn field(stream: &mut Stream<'_>) -> io::Result<Option<(u8, u64)>> {
    let kind = stream.read_u8().await?;
    let size = stream.read_u8().await?;
    if size & 0x80 == 0 {
        return Ok(Some((kind, u64::from(size))));
    }
    let count = size & 0x7f;
    if count == 0 || usize::from(count) > size_of::<u64>() {
        return Ok(None);
    }
    let mut size = 0;
    for _ in 0..count {
        size = size << 8 | u64::from(stream.read_u8().await?);
    }
    Ok(Some((kind, size)))
}

async fn integer(stream: &mut Stream<'_>, kind: u8, end: u64) -> io::Result<Option<u32>> {
    let Some((tag, size)) = field(stream).await? else {
        return Ok(None);
    };
    if tag != kind
        || size == 0
        || size > size_of::<u32>() as u64
        || size > end.saturating_sub(stream.read)
    {
        return Ok(None);
    }
    let mut value = 0;
    for _ in 0..size {
        value = value << 8 | u32::from(stream.read_u8().await?);
    }
    Ok(Some(value))
}

fn length(data: &[u8], position: usize) -> Option<(u64, usize)> {
    let first = *data.get(position)?;
    if first & 0x80 == 0 {
        return Some((u64::from(first), position + 1));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > size_of::<u64>() {
        return Some((0, position + 1));
    }
    let bytes = data.get(position + 1..position + 1 + count)?;
    Some((
        bytes
            .iter()
            .fold(0, |value, &byte| value << 8 | u64::from(byte)),
        position + 1 + count,
    ))
}

fn number(data: &[u8]) -> Option<u64> {
    if data.is_empty() {
        return None;
    }
    data.iter().try_fold(0u64, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value.checked_mul(10)?.checked_add(u64::from(byte - b'0')))?
    })
}

fn literal(line: &[u8]) -> Option<(u64, bool)> {
    let value = line.strip_suffix(b"}")?;
    let start = value.iter().rposition(|&byte| byte == b'{')?;
    let value = &value[start + 1..];
    let asynchronous = value.ends_with(b"+");
    let value = value.strip_suffix(b"+").unwrap_or(value);
    Some((number(value)?, asynchronous))
}
