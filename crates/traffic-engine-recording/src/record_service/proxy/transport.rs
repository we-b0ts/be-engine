//! Owned upgrade tasks and cancellation-aware response body delivery.

use super::*;
use std::{
    future::Future,
    sync::{Mutex, Weak},
};

#[derive(Clone)]
pub(super) struct TransportTasks(Arc<TransportState>);

struct TransportState {
    tasks: Mutex<Vec<AbortOnDrop>>,
    cancel: watch::Sender<bool>,
}

#[derive(Clone)]
pub(super) struct WeakTransportTasks(Weak<TransportState>);

impl WeakTransportTasks {
    pub(super) fn upgrade(&self) -> Option<TransportTasks> {
        self.0.upgrade().map(TransportTasks)
    }
    pub(super) fn matches(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}

impl Default for TransportTasks {
    fn default() -> Self {
        let (cancel, _) = watch::channel(false);
        Self(Arc::new(TransportState {
            tasks: Mutex::new(Vec::new()),
            cancel,
        }))
    }
}

impl TransportTasks {
    pub(super) fn downgrade(&self) -> WeakTransportTasks {
        WeakTransportTasks(Arc::downgrade(&self.0))
    }
    pub(super) fn cancellation(&self) -> watch::Receiver<bool> {
        self.0.cancel.subscribe()
    }
    pub(super) fn cancel(&self) {
        self.0.cancel.send_replace(true);
    }

    pub(super) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        self.0
            .tasks
            .lock()
            .expect("relay transport tasks poisoned")
            .push(AbortOnDrop(tokio::spawn(task)));
    }

    pub(super) async fn finish(&self) {
        let tasks =
            std::mem::take(&mut *self.0.tasks.lock().expect("relay transport tasks poisoned"));
        for mut task in tasks {
            if let Err(error) = (&mut task.0).await {
                warn!(%error, "relay transport task failed");
            }
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    if !*cancel.borrow() {
        let _ = cancel.changed().await;
    }
}

pub(super) fn body(body: Incoming, cancel: Option<watch::Receiver<bool>>) -> RelayBody {
    response_body(body, cancel, None)
}

pub(super) fn finite_body(
    body: Incoming,
    cancel: Option<watch::Receiver<bool>>,
    finished: tokio::sync::oneshot::Sender<()>,
) -> RelayBody {
    response_body(body, cancel, Some(finished))
}

fn response_body(
    body: Incoming,
    cancel: Option<watch::Receiver<bool>>,
    finished: Option<tokio::sync::oneshot::Sender<()>>,
) -> RelayBody {
    let finite = finished.is_some();
    let stream = futures_util::stream::unfold(
        (body, cancel, finished),
        move |(mut body, mut cancel, finished)| async move {
            let frame = if let Some(cancel) = &mut cancel {
                tokio::select! {
                    frame = body.frame() => frame.map(|frame| frame.map_err(|error| Box::new(error) as RelayError)),
                    _ = cancelled(cancel) => finite.then(|| Err(Box::new(std::io::Error::other("finite response delivery cancelled")) as RelayError)),
                }
            } else {
                body.frame()
                    .await
                    .map(|frame| frame.map_err(|error| Box::new(error) as RelayError))
            };
            frame.map(|frame| (frame, (body, cancel, finished)))
        },
    );
    http_body_util::StreamBody::new(stream).boxed_unsync()
}
