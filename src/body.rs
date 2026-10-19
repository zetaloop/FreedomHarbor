use std::{
    collections::VecDeque,
    future::poll_fn,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use hyper::body::{Body as HttpBody, Bytes, Frame, Incoming, SizeHint};

use crate::protocol::{Probe, Protocol};

pub type ResponseBody = UnsyncBoxBody<Bytes, anyhow::Error>;

pub fn empty() -> ResponseBody {
    Empty::<Bytes>::new()
        .map_err(anyhow::Error::from)
        .boxed_unsync()
}

#[derive(Clone)]
pub struct Body(Arc<Mutex<Stream>>);

struct Stream {
    inner: Incoming,
    prefix: VecDeque<Frame<Bytes>>,
}

impl Body {
    pub fn new(body: Incoming) -> Self {
        Self(Arc::new(Mutex::new(Stream {
            inner: body,
            prefix: VecDeque::new(),
        })))
    }

    pub async fn protocol(&self) -> Result<Protocol, hyper::Error> {
        let mut probe = Probe::new(false, false);
        poll_fn(|cx| {
            let mut stream = self.0.lock().expect("body lock poisoned");
            loop {
                let Some(frame) = ready!(Pin::new(&mut stream.inner).poll_frame(cx)) else {
                    return Poll::Ready(Ok(Protocol::Tcp));
                };
                let frame = frame?;
                if frame.data_ref().is_some_and(Bytes::is_empty) {
                    continue;
                }
                let protocol = frame
                    .data_ref()
                    .map_or(Some(Protocol::Tcp), |data| probe.feed(data));
                stream.prefix.push_back(frame);
                if let Some(protocol) = protocol {
                    return Poll::Ready(Ok(protocol));
                }
            }
        })
        .await
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let mut stream = self.0.lock().expect("body lock poisoned");
        if let Some(frame) = stream.prefix.pop_front() {
            Poll::Ready(Some(Ok(frame)))
        } else {
            Pin::new(&mut stream.inner).poll_frame(cx)
        }
    }

    fn is_end_stream(&self) -> bool {
        let stream = self.0.lock().expect("body lock poisoned");
        stream.prefix.is_empty() && stream.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let stream = self.0.lock().expect("body lock poisoned");
        let prefix = stream
            .prefix
            .iter()
            .filter_map(Frame::data_ref)
            .map(|data| data.len() as u64)
            .sum::<u64>();
        let remaining = stream.inner.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(prefix + remaining.lower());
        if let Some(upper) = remaining.upper() {
            hint.set_upper(prefix + upper);
        }
        hint
    }
}
