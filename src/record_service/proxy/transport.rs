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
    let stream =
        futures_util::stream::unfold((body, cancel), |(mut body, mut cancel)| async move {
            let frame = if let Some(cancel) = &mut cancel {
                tokio::select! {
                    frame = body.frame() => frame,
                    _ = cancelled(cancel) => None,
                }
            } else {
                body.frame().await
            };
            frame.map(|frame| (frame.map_err(|e| Box::new(e) as RelayError), (body, cancel)))
        });
    http_body_util::StreamBody::new(stream).boxed_unsync()
}
