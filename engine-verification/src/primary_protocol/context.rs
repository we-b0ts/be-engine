//! Per-execution authority and clocks are independent of native input encoding.
use std::{path::Path, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use tokio::{sync::watch, time::Instant};

pub struct ExecutionSettings<'a> {
    pub http_origin: &'a str,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub socketio_timing: crate::interaction::replay::timing::SocketIoTiming,
}

pub struct CaseExecutionContext<'a> {
    pub case_id: &'a str,
    pub session_path: &'a Path,
    pub request_path: &'a Path,
    pub request_rules: Arc<crate::request_rules::RequestRuleRuntime>,
    pub dependency_failure: Option<watch::Receiver<bool>>,
    pub settings: ExecutionSettings<'a>,
    pub deadline: Instant,
}

impl CaseExecutionContext<'_> {
    pub fn remaining(&self) -> Duration {
        self.settings
            .request_timeout
            .min(self.deadline.saturating_duration_since(Instant::now()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CaseClock {
    pub source_request_started_at: Option<DateTime<Utc>>,
    pub target_request_started_at: DateTime<Utc>,
}

impl CaseClock {
    pub fn anchors(self) -> crate::policy_evidence::ClockPair {
        crate::policy_evidence::ClockPair {
            source: self.source_request_started_at,
            target: Some(self.target_request_started_at),
        }
    }
}
