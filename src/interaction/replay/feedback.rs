//! Actual transport metadata and dependency rejection feedback for input execution.
use anyhow::Result;
use futures_util::future::BoxFuture;
use std::sync::Arc;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeEvent {
    pub namespace: String,
    pub event: String,
    pub ordinal: u64,
}

pub(crate) trait NativeEventSink: Send + Sync {
    fn observe(&self, event: NativeEvent) -> BoxFuture<'_, Result<()>>;
    fn connected<'a>(
        &'a self,
        _namespace: &'a str,
        _sid: Option<&'a str>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn acknowledged(&self, _sequence: u64) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Default)]
pub(crate) struct Feedback {
    pub dependency_failure: Option<tokio::sync::watch::Receiver<bool>>,
    pub native_events: Option<Arc<dyn NativeEventSink>>,
    pub event_order: Option<super::event_order::Order>,
    pub input_timing: Option<Arc<dyn super::timing::InputTiming>>,
}

impl From<Option<tokio::sync::watch::Receiver<bool>>> for Feedback {
    fn from(dependency_failure: Option<tokio::sync::watch::Receiver<bool>>) -> Self {
        Self {
            dependency_failure,
            ..Self::default()
        }
    }
}
