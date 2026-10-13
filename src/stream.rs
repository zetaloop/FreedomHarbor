use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, ready},
};

use hyper::body::{Buf, Bytes};
use hyper_util::client::legacy::connect::{Connected, Connection};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

pub struct Stream {
    pub socket: TcpStream,
    pub prefix: Bytes,
    pub proxied: bool,
    output: Bytes,
    skip: usize,
    ack: Ack,
}

#[derive(Default)]
enum Ack {
    Preface(usize),
    Header([u8; 9], usize),
    Frame([u8; 9], usize, usize),
    #[default]
    Done,
}

impl Stream {
    pub fn new(socket: TcpStream) -> io::Result<Self> {
        socket.set_nodelay(true)?;
        Ok(Self {
            socket,
            prefix: Bytes::new(),
            proxied: false,
            output: Bytes::new(),
            skip: 0,
            ack: Ack::Done,
        })
    }

    pub async fn connect(destination: SocketAddr) -> io::Result<Self> {
        Self::new(TcpStream::connect(destination).await?)
    }

    pub fn resume(&mut self, response: &[u8], sent: usize) {
        if sent == 0 {
            return;
        }
        if response.starts_with(b"HTTP/") || b"HTTP/".starts_with(response) {
            self.skip = sent;
            return;
        }

        // SETTINGS identifier 0 is reserved and ignored by peers.
        let mut settings = vec![0; 9 + frame_length(response)];
        settings[..9].copy_from_slice(&response[..9]);
        self.output = Bytes::from(settings).slice(sent..);
        self.ack = Ack::Preface(24);
    }

    fn poll_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.output.is_empty() {
            let count = ready!(Pin::new(&mut self.socket).poll_write(cx, &self.output))?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.output.advance(count);
            if self.output.is_empty() {
                self.output = Bytes::new();
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Connection for Stream {
    fn connected(&self) -> Connected {
        self.socket.connected().proxy(self.proxied)
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let Self {
            socket,
            prefix,
            ack,
            ..
        } = self.get_mut();

        loop {
            match ack {
                Ack::Done => return poll_read(socket, prefix, cx, buf),
                Ack::Preface(remaining) => {
                    let count = (*remaining).min(buf.remaining());
                    let mut part = ReadBuf::new(buf.initialize_unfilled_to(count));
                    ready!(poll_read(socket, prefix, cx, &mut part))?;
                    let count = part.filled().len();
                    buf.advance(count);
                    *remaining -= count;
                    if *remaining == 0 {
                        *ack = Ack::Header([0; 9], 0);
                    }
                    return Poll::Ready(Ok(()));
                }
                Ack::Header(header, filled) => {
                    let mut part = ReadBuf::new(&mut header[*filled..]);
                    ready!(poll_read(socket, prefix, cx, &mut part))?;
                    let count = part.filled().len();
                    if count == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    *filled += count;
                    if *filled == header.len() {
                        let length = frame_length(header);
                        if length == 0
                            && header[3] == 4
                            && header[4] & 1 != 0
                            && header[5] & 0x7f == 0
                            && header[6..] == [0, 0, 0]
                        {
                            *ack = Ack::Done;
                        } else {
                            *ack = Ack::Frame(*header, 0, length);
                        }
                    }
                }
                Ack::Frame(header, sent, remaining) => {
                    if *sent < header.len() {
                        let count = (header.len() - *sent).min(buf.remaining());
                        buf.put_slice(&header[*sent..*sent + count]);
                        *sent += count;
                        return Poll::Ready(Ok(()));
                    }
                    if *remaining == 0 {
                        *ack = Ack::Header([0; 9], 0);
                        continue;
                    }
                    let count = (*remaining).min(buf.remaining());
                    let mut part = ReadBuf::new(buf.initialize_unfilled_to(count));
                    ready!(poll_read(socket, prefix, cx, &mut part))?;
                    let count = part.filled().len();
                    buf.advance(count);
                    *remaining -= count;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_output(cx))?;
        if this.skip != 0 {
            let count = this.skip.min(buf.len());
            this.skip -= count;
            return Poll::Ready(Ok(count));
        }
        Pin::new(&mut this.socket).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_output(cx))?;
        Pin::new(&mut this.socket).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_output(cx))?;
        Pin::new(&mut this.socket).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.output.is_empty() && self.skip == 0 && self.socket.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.is_write_vectored() {
            Pin::new(&mut self.get_mut().socket).poll_write_vectored(cx, bufs)
        } else {
            self.poll_write(
                cx,
                bufs.iter()
                    .find(|buf| !buf.is_empty())
                    .map_or(&[], |buf| &buf[..]),
            )
        }
    }
}

fn poll_read(
    socket: &mut TcpStream,
    prefix: &mut Bytes,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    if prefix.is_empty() {
        Pin::new(socket).poll_read(cx, buf)
    } else {
        let count = prefix.len().min(buf.remaining());
        buf.put_slice(&prefix[..count]);
        prefix.advance(count);
        if prefix.is_empty() {
            *prefix = Bytes::new();
        }
        Poll::Ready(Ok(()))
    }
}

fn frame_length(header: &[u8]) -> usize {
    (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2])
}
