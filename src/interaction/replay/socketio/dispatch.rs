//! Driver-side state for one ordered input. The control owner retains the clock
//! and the proof of which resource requests have actually been admitted.
use std::sync::Arc;

use anyhow::Result;
use futures_util::future::BoxFuture;
use tokio::sync::watch;

use crate::interaction::{
    model::{DispatchDependency, InputAction},
    replay::timing::{Advance, InputTiming},
};

pub(super) struct Dispatch {
    events_ready: watch::Sender<bool>,
    unadmitted: watch::Receiver<Option<DispatchDependency>>,
}

impl Dispatch {
    pub(super) fn begin(
        timing: Arc<dyn InputTiming>,
        action: &InputAction,
        ready: bool,
    ) -> (Self, BoxFuture<'static, Result<Advance>>) {
        let (events_ready, events) = watch::channel(ready);
        let (missing, unadmitted) = watch::channel(None);
        let (sequence, completed) = (action.sequence, action.after.clone());
        let wait = Box::pin(async move {
            timing
                .wait_dispatch(sequence, completed, events, missing)
                .await
        });
        (
            Self {
                events_ready,
                unadmitted,
            },
            wait,
        )
    }

    pub(super) fn events_arrived(&self) {
        self.events_ready
            .send_if_modified(|ready| !std::mem::replace(ready, true));
    }

    pub(super) fn unadmitted(&self) -> Option<DispatchDependency> {
        self.unadmitted.borrow().clone()
    }
}
