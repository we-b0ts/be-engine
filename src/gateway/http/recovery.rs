//! Supervise a timed-out Source request without releasing its case admission slot.

use chrono::{DateTime, Utc};
use std::{future::Future, time::Duration};
use tokio::sync::oneshot;
use tracing::warn;

use crate::AppState;
use crate::recorder::CaseContext;
use crate::recorder::CaseInvalidation;
use crate::recorder::connections::ConnectionResetReport;

pub(super) struct TimeoutRecovery {
    state: AppState,
    case: CaseContext,
    timeout_ms: u128,
    downstream: Option<oneshot::Sender<()>>,
    reset: Option<ConnectionResetReport>,
    timed_out_at: Option<DateTime<Utc>>,
    recovery_timed_out_at: Option<DateTime<Utc>>,
    source_completed: bool,
}

impl TimeoutRecovery {
    pub(super) fn new(
        state: AppState,
        case: CaseContext,
        timeout_ms: u128,
    ) -> (Self, oneshot::Receiver<()>) {
        let (downstream, receiver) = oneshot::channel();
        (
            Self {
                state,
                case,
                timeout_ms,
                downstream: Some(downstream),
                reset: None,
                timed_out_at: None,
                recovery_timed_out_at: None,
                source_completed: false,
            },
            receiver,
        )
    }

    pub(super) async fn observe_source_completion<F>(&mut self, operation: F)
    where
        F: Future<Output = anyhow::Result<()>>,
    {
        let budget_ms = self
            .state
            .config()
            .recording
            .case_dependency_drain_timeout_ms;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(budget_ms);
        self.begin().await;
        tokio::pin!(operation);
        let result = match tokio::time::timeout_at(deadline, &mut operation).await {
            Ok(result) => result,
            Err(_) => {
                self.recovery_timed_out_at = Some(Utc::now());
                self.persist(
                    "source_recovery_timeout",
                    Some(format!(
                        "Source did not finish within the {budget_ms} ms recovery budget after the HTTP request timed out"
                    )),
                )
                .await;
                self.state.begin_case_quiescing();
                warn!(case_id = %self.case.id, recovery_timeout_ms = budget_ms,
                    "HTTP timeout recovery exceeded its budget; requesting Source shutdown while retaining request ownership");
                // The recording supervisor owns Source termination. Keep the
                // original request/body future until that process exits so its
                // transport outcome and dependency evidence can still finalize.
                operation.await
            }
        };
        self.source_finished(&result).await;
    }

    async fn begin(&mut self) {
        if !self.state.inner.active_cases.begin_timeout_recovery(
            self.case.id,
            format!(
                "gateway upstream request timed out after {} ms",
                self.timeout_ms
            ),
        ) {
            return;
        }
        self.timed_out_at = Some(Utc::now());
        if let Some(downstream) = self.downstream.take() {
            let _ = downstream.send(());
        }
        let reset = self.state.dependency_connections().reset_open_connections();
        warn!(case_id = %self.case.id, connections_by_protocol = ?reset.connections_by_protocol, reset_errors = ?reset.errors, "timed-out HTTP case retains admission while dependency connections are reset");
        self.reset = Some(reset);
        self.persist("waiting_for_source", None).await;
    }

    async fn source_finished(&mut self, result: &anyhow::Result<()>) {
        match result {
            Ok(_) => {
                self.source_completed = true;
                self.state
                    .inner
                    .active_cases
                    .source_request_completed(self.case.id);
                self.persist("source_completed", None).await;
            }
            Err(error) => {
                // EOF/errors on the HTTP transport cannot prove the handler has ended.
                self.state.begin_case_quiescing();
                self.persist("source_completion_unconfirmed", Some(format!("{error:#}")))
                    .await;
                warn!(case_id = %self.case.id, %error, "Source completion is unconfirmed; recording case admission stopped");
            }
        }
    }

    pub(super) async fn dependencies_drained(&self, invalidation: Option<&CaseInvalidation>) {
        if !self.source_completed {
            return;
        }
        if let Some(invalidation) = invalidation {
            self.persist(
                "dependency_drain_timed_out",
                Some(invalidation.message.clone()),
            )
            .await;
        } else {
            self.persist("completed", None).await;
        }
    }

    async fn persist(&self, phase: &str, error: Option<String>) {
        let report = serde_json::json!({
            "timestamp": Utc::now(),
            "timed_out_at": self.timed_out_at,
            "source_recovery_timed_out_at": self.recovery_timed_out_at,
            "source_recovery_timeout_ms": self.state.config().recording.case_dependency_drain_timeout_ms,
            "stop_reason": self.recovery_timed_out_at.as_ref().map(|_| "source_recovery_timeout"),
            "case_id": self.case.id,
            "request_timeout_ms": self.timeout_ms,
            "phase": phase,
            "reset": self.reset,
            "error": error,
            "dependency_quiet_ms": self.state.config().recording.case_dependency_post_response_window_ms,
            "dependency_drain_timeout_ms": self.state.config().recording.case_dependency_drain_timeout_ms,
        });
        if let Err(error) = self
            .state
            .recorder()
            .write_case_json(&self.case, "timeout-recovery.json", &report)
            .await
        {
            warn!(case_id = %self.case.id, %error, "failed to persist HTTP timeout recovery diagnostics");
        }
    }
}
