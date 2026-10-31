//! Per-execution authority and clocks are independent of native input encoding.
use std::{path::Path, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use tokio::{sync::watch, time::Instant};

pub(crate) struct ExecutionSettings<'a> {
    pub(crate) http_origin: &'a str,
    pub(crate) motan_upstream: Option<&'a str>,
    pub(crate) request_timeout: Duration,
    pub(crate) max_response_bytes: usize,
    pub(crate) motan_limits: motan_protocol::Limits,
    pub(crate) socketio_timing: crate::interaction::replay::timing::SocketIoTiming,
}

pub(crate) struct CaseExecutionContext<'a> {
    pub(crate) case_id: &'a str,
    pub(crate) session_path: &'a Path,
    pub(crate) request_path: &'a Path,
    pub(crate) request_rules: Arc<crate::request_rules::RequestRuleRuntime>,
    pub(crate) dependency_failure: Option<watch::Receiver<bool>>,
    pub(crate) settings: ExecutionSettings<'a>,
    pub(crate) deadline: Instant,
}

impl CaseExecutionContext<'_> {
    pub(crate) fn remaining(&self) -> Duration {
        self.settings
            .request_timeout
            .min(self.deadline.saturating_duration_since(Instant::now()))
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CaseClock {
    pub(crate) source_request_started_at: Option<DateTime<Utc>>,
    pub(crate) target_request_started_at: DateTime<Utc>,
}

impl CaseClock {
    pub(crate) fn anchors(self) -> crate::policy_evidence::ClockPair {
        crate::policy_evidence::ClockPair {
            source: self.source_request_started_at,
            target: Some(self.target_request_started_at),
        }
    }
}
