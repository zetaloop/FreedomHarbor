use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use hyper::body::{Body as HttpBody, Bytes, Frame, Incoming, SizeHint};

#[derive(Clone)]
pub struct Body(Arc<Mutex<Incoming>>);

impl Body {
    pub fn new(body: Incoming) -> Self {
        Self(Arc::new(Mutex::new(body)))
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Pin::new(&mut *self.0.lock().expect("body lock poisoned")).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0.lock().expect("body lock poisoned").is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.lock().expect("body lock poisoned").size_hint()
    }
}
