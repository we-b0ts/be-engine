//! Bounded transport facts; never retain payloads, headers or error text.

use super::{ClientTermination, ObservedTermination};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
    time::Instant,
};
use traffic_model::{DependencyTermination, TerminationKind, TerminationScope, TerminationSide};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum IoLayer {
    Http,
    Transport,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum IoOperation {
    Read,
    Write,
    Flush,
    Peek,
}

struct Failure {
    at: Instant,
    kind: io::ErrorKind,
    os_error: Option<i32>,
}

#[derive(Clone, Default)]
pub(super) struct IoDiagnosis(Arc<Mutex<BTreeMap<(IoLayer, IoOperation), Failure>>>);

impl IoDiagnosis {
    fn has_transport_failure_since(&self, started: Instant) -> bool {
        self.0
            .lock()
            .expect("HTTP IO diagnosis poisoned")
            .values()
            .any(|failure| {
                failure.at >= started
                    && traffic_protocol::transport::is_connection_termination(failure.kind)
            })
    }

    pub(super) fn record(&self, layer: IoLayer, operation: IoOperation, error: &io::Error) {
        // Two layers and four operations bound this map to eight entries.
        self.0
            .lock()
            .expect("HTTP IO diagnosis poisoned")
            .entry((layer, operation))
            .or_insert_with(|| Failure {
                at: Instant::now(),
                kind: error.kind(),
                os_error: error.raw_os_error(),
            });
    }

    fn since(&self, started: Instant) -> Vec<serde_json::Value> {
        self.0
            .lock()
            .expect("HTTP IO diagnosis poisoned")
            .iter()
            .filter_map(|((layer, operation), failure)| {
                let elapsed = failure.at.checked_duration_since(started)?;
                Some(serde_json::json!({
                    "layer": layer, "operation": operation,
                    "at_ms": elapsed.as_millis(),
                    "kind": format!("{:?}", failure.kind),
                    "os_error": failure.os_error,
                }))
            })
            .collect()
    }
}

pub fn observed_since(
    observed: Option<ObservedTermination>,
    started: Instant,
) -> Option<serde_json::Value> {
    let observed = observed?;
    Some(serde_json::json!({ "termination": observed.termination,
        "at_ms": observed.at.checked_duration_since(started)?.as_millis() }))
}

impl ClientTermination {
    pub fn has_transport_failure_since(&self, started: Instant) -> bool {
        self.io_diagnosis.has_transport_failure_since(started)
    }

    pub(crate) fn stream_cancelled_since(&self, started: Instant) -> Option<ObservedTermination> {
        if let Some(closed) = self.cancelled().filter(|closed| closed.at >= started) {
            return Some(closed);
        }
        let fin = self
            .observed()
            .filter(|fin| fin.at >= started && fin.termination.kind == TerminationKind::Eof)?;
        let write_failure = self
            .io_diagnosis
            .0
            .lock()
            .expect("HTTP IO diagnosis poisoned")
            .iter()
            .filter(|((_, operation), failure)| {
                matches!(operation, IoOperation::Write | IoOperation::Flush)
                    && failure.at >= started
                    && traffic_protocol::transport::is_connection_termination(failure.kind)
            })
            .map(|(_, failure)| failure.at)
            .min()?;
        Some(ObservedTermination {
            termination: DependencyTermination {
                side: TerminationSide::Client,
                kind: TerminationKind::Cancelled,
                scope: TerminationScope::Stream,
            },
            at: fin.at.max(write_failure),
        })
    }

    pub(crate) fn has_failed_delivery_before(&self, started: Instant, boundary: Instant) -> bool {
        self.io_diagnosis
            .0
            .lock()
            .expect("HTTP IO diagnosis poisoned")
            .iter()
            .any(|((_, operation), failure)| {
                failure.at >= started
                    && failure.at <= boundary
                    && (matches!(operation, IoOperation::Write | IoOperation::Flush)
                        || matches!(
                            failure.kind,
                            io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
                        ))
            })
    }

    pub fn diagnosis(&self, started: Instant) -> serde_json::Value {
        serde_json::json!({
            "engine_stopped": self.engine_stopped(),
            "client_first": observed_since(self.observation.observed(traffic_model::TerminationSide::Client), started),
            "client_connection_end": observed_since(self.cancelled(), started),
            "io_errors": self.io_diagnosis.since(started),
        })
    }

    pub(super) fn observe_io_error(
        &self,
        layer: IoLayer,
        operation: IoOperation,
        error: &io::Error,
    ) {
        self.io_diagnosis.record(layer, operation, error);
        self.observe_error(error);
    }
}
