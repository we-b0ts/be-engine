//! Ordinary bodies complete only after their final bytes cross the HTTP writer.
use super::*;
use crate::http::termination::DeliveryProgress;

#[cfg(test)]
mod tests;

pub(in crate::replay::http) struct Transport {
    pub observation: Option<crate::http::termination::ClientTermination>,
    pub progress: DeliveryProgress,
    pub finished: tokio::sync::watch::Receiver<bool>,
}

struct FullDelivery {
    inner: Full<Bytes>,
    completion: Option<DeliveryCompletion>,
    flushed: Arc<PrefixDelivery>,
    finished: tokio::sync::watch::Receiver<bool>,
    empty: bool,
}

impl FullDelivery {
    fn queue(&mut self) {
        let Some(mut completion) = self.completion.take() else {
            return;
        };
        self.flushed.queued();
        let flushed = self.flushed.clone();
        let mut finished = self.finished.clone();
        tokio::spawn(async move {
            let result = loop {
                // A final successful flush wins over the subsequent normal
                // connection close, including Connection: close responses.
                if flushed.is_complete() {
                    break Ok(());
                }
                if *finished.borrow() {
                    break Err(anyhow!(
                        "HTTP dependency transport ended before its ordinary response was flushed"
                    ));
                }
                tokio::select! {
                    _ = flushed.wait() => {},
                    result = finished.changed() => {
                        if result.is_err() && !flushed.is_complete() {
                            break Err(anyhow!("HTTP dependency transport disappeared before response delivery"));
                        }
                    }
                }
            };
            completion.apply(result).await;
        });
    }
}

impl Body for FullDelivery {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(never))) => match never {},
            Poll::Ready(None) => Poll::Ready(None),
        };
        if this.inner.is_end_stream() {
            this.queue();
        }
        frame
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for FullDelivery {
    fn drop(&mut self) {
        if self.empty {
            // Hyper can discard an empty/HEAD/204 Body without polling it.
            // Header delivery still needs the actual connection flush below.
            self.queue();
        }
        // A nonempty unpolled body retains DeliveryCompletion, whose Drop
        // records failure. Queueing never manufactures a consumed exchange.
    }
}

pub(super) fn response(
    response: Response<Full<Bytes>>,
    completion: DeliveryCompletion,
    transport: Transport,
) -> Response<DeliveryBody> {
    response.map(|inner| {
        let empty = inner.is_end_stream();
        let mut body = FullDelivery {
            inner,
            completion: Some(completion),
            flushed: Arc::new(PrefixDelivery::new(transport.progress)),
            finished: transport.finished,
            empty,
        };
        if empty {
            body.queue();
        }
        body.boxed()
    })
}
