//! Reserve zero-response HTTP exchanges until the observed client termination.
use super::super::{ReplayExchangeStatus, ReplayExchangeTiming};
use super::*;
use crate::dependency::termination::ConnectionControl;
use crate::http::termination::PrefixDelivery;
use tokio::time::Instant;

pub(super) struct PendingHttpTermination {
    pub(super) detail: MatchedHttpExchangeReport,
    pub(super) timing: ReplayExchangeTiming,
    pub(super) started: Instant,
    pub(super) prefix_delivered: Option<Arc<PrefixDelivery>>,
    pub(super) expected_termination: Option<crate::dependency::DependencyTermination>,
    pub(super) server_result: Option<Result<(), String>>,
}

impl PendingHttpTermination {
    pub(super) fn observed_client(
        &self,
        termination: &crate::http::termination::ClientTermination,
    ) -> Option<crate::http::termination::ObservedTermination> {
        if self.expected_termination.is_some_and(|end| {
            end.side == crate::dependency::TerminationSide::Client
                && end.kind == crate::dependency::TerminationKind::Eof
        }) {
            termination.observed()
        } else {
            // HTTP/1 write-half EOF still permits a delayed response. Only a
            // connection end proves cancellation of a response in progress.
            termination.cancelled()
        }
    }

    pub(super) fn new(detail: MatchedHttpExchangeReport, record: &RecordedHttpExchange) -> Self {
        Self {
            detail,
            timing: ReplayExchangeTiming::from_recorded(
                record
                    .duration_ms
                    .as_ref()
                    .and_then(Value::as_u64)
                    .expect("validated HTTP termination duration"),
                record.outcome,
            ),
            started: Instant::now(),
            prefix_delivered: None,
            expected_termination: record.outcome.termination(),
            server_result: None,
        }
    }

    pub(super) fn validate(
        &self,
        observed: crate::http::termination::ObservedTermination,
    ) -> Result<()> {
        self.timing.validate_client_termination(
            Instant::from_std(observed.at).saturating_duration_since(self.started),
        )?;
        anyhow::ensure!(
            self.prefix_delivered
                .as_ref()
                .is_none_or(|delivered| delivered.is_complete()),
            "Target terminated HTTP dependency before its recorded response prefix was delivered"
        );
        if let Some(expected) = self.expected_termination {
            anyhow::ensure!(
                expected == observed.termination,
                "Target HTTP dependency termination differs from the recorded mechanism or scope"
            );
        }
        Ok(())
    }
}

/// The transport owner closes IO only after the timed response prefix is flushed.
pub(super) struct ServerClose {
    control: ConnectionControl,
    observation: crate::http::termination::ClientTermination,
    pending: Arc<std::sync::Mutex<Option<PendingHttpTermination>>>,
    closed: tokio::sync::watch::Sender<bool>,
    end: crate::dependency::DependencyTermination,
    deadline: Instant,
}

impl ServerClose {
    pub(super) fn new(
        control: ConnectionControl,
        observation: crate::http::termination::ClientTermination,
        pending: Arc<std::sync::Mutex<Option<PendingHttpTermination>>>,
        closed: tokio::sync::watch::Sender<bool>,
        end: crate::dependency::DependencyTermination,
        deadline: Instant,
    ) -> Self {
        Self {
            control,
            observation,
            pending,
            closed,
            end,
            deadline,
        }
    }

    pub(super) fn finish(self) {
        use crate::dependency::{TerminationKind, TerminationScope};
        let result = match (self.end.kind, self.end.scope) {
            (TerminationKind::Eof, TerminationScope::WriteHalf) => self
                .control
                .shutdown_write()
                .map(|()| self.observation.mark_server_write_half_closed()),
            (TerminationKind::Reset, TerminationScope::Connection) => self.control.reset(),
            _ => Err(std::io::Error::other("unsupported HTTP server termination")),
        };
        self.report(result.map_err(|error| error.to_string()));
    }

    pub(super) fn after_prefix(self, prefix: Arc<PrefixDelivery>) {
        tokio::spawn(async move {
            if tokio::time::timeout_at(self.deadline, prefix.wait())
                .await
                .is_err()
            {
                self.report(Err(
                    "HTTP response prefix was not flushed before the server termination deadline"
                        .into(),
                ));
            } else {
                self.finish();
            }
        });
    }

    fn report(self, result: Result<(), String>) {
        if let Some(pending) = self
            .pending
            .lock()
            .expect("HTTP pending termination poisoned")
            .as_mut()
        {
            pending.server_result = Some(result);
        }
        self.closed.send_replace(true);
    }
}

pub(super) fn validate_record(record: &RecordedHttpExchange) -> Result<()> {
    if record.outcome == crate::DependencyExchangeOutcome::NoResponse {
        return Err(anyhow!(
            "HTTP does not support a protocol-level no_response outcome"
        ));
    }
    if !record.outcome.is_client_terminated() && !record.outcome.is_server_terminated() {
        anyhow::ensure!(
            record.outcome.termination().is_none(),
            "HTTP engine-owned termination is not replayable peer evidence"
        );
        return Ok(());
    }
    if let Some(end) = record.outcome.termination() {
        use crate::dependency::{TerminationKind, TerminationScope};
        anyhow::ensure!(
            matches!(
                (end.kind, end.scope),
                (TerminationKind::Eof, TerminationScope::WriteHalf)
                    | (TerminationKind::Reset, TerminationScope::Connection)
            ),
            "HTTP/1 replay requires an observed write-half EOF or connection reset; stream-local cancellation is unsupported"
        );
    }
    anyhow::ensure!(
        record.error.is_none(),
        "HTTP client termination contains an upstream/capture error"
    );
    if let Some(stream) = &record.response_stream {
        anyhow::ensure!(
            stream.version == 2 && record.outcome.termination().is_some(),
            "HTTP cancelled response prefixes require version-2 termination evidence; re-record this case"
        );
        anyhow::ensure!(
            record.response_status.is_some() && record.response_headers.is_some(),
            "HTTP cancelled response prefix has no response headers"
        );
        anyhow::ensure!(
            stream.trailers.is_none(),
            "HTTP cancelled response prefix cannot contain terminal trailers"
        );
        let body = record
            .response_body
            .as_ref()
            .context("HTTP cancelled response prefix has no payload")?;
        let payload_len = if record.response_evidence.is_some() {
            body.stored_len
                .context("deferred HTTP cancelled stream has no payload length")?
        } else {
            decode_body(body)?.len()
        };
        stream.validate(payload_len)?;
        anyhow::ensure!(
            record.duration_ms.as_ref().and_then(Value::as_u64) == Some(stream.end_ms),
            "HTTP cancelled stream duration and termination time disagree"
        );
    } else {
        anyhow::ensure!(
            record.response_status.is_none() && record.response_headers.is_none(),
            "HTTP client termination contains response headers"
        );
        anyhow::ensure!(
            record
                .response_body
                .as_ref()
                .map(decode_body)
                .transpose()?
                .is_none_or(|body| body.is_empty()),
            "HTTP client termination contains response bytes"
        );
    }
    anyhow::ensure!(
        record
            .duration_ms
            .as_ref()
            .and_then(Value::as_u64)
            .is_some(),
        "HTTP client termination requires an integer duration_ms"
    );
    Ok(())
}

impl ReplayState {
    pub(super) fn complete_http_exchange(&mut self, mut detail: MatchedHttpExchangeReport) {
        let budget_case_id = detail.case_id.clone();
        push_success_detail(
            &mut self.http_events.matched_count,
            &mut self.http_events.matched,
            &mut self.http_events.matched_details,
            budget_case_id.as_deref(),
            |target_event_index| {
                detail.target_event_index = target_event_index;
                detail
            },
        );
    }

    pub(super) fn finish_http_termination(
        &mut self,
        pending: PendingHttpTermination,
        result: Result<()>,
    ) {
        self.finish_http_response(pending.detail, result);
    }

    pub(super) fn finish_http_response(
        &mut self,
        detail: MatchedHttpExchangeReport,
        result: Result<()>,
    ) {
        match result {
            Ok(()) => {
                self.http_exchanges[detail.index].status = ReplayExchangeStatus::Consumed;
                self.refresh_http_global_report(detail.index);
                self.complete_http_exchange(detail);
            }
            Err(error) => {
                self.http_exchanges[detail.index].status = ReplayExchangeStatus::Failed;
                self.refresh_http_global_report(detail.index);
                if let Some(case_id) = &detail.case_id {
                    self.http_events.dirty_case_ids.insert(case_id.clone());
                }
                self.http_events.unsupported.push(HttpRequestReport {
                    case_id: detail.case_id,
                    scheme: detail.scheme,
                    target: detail.target,
                    method: detail.method,
                    uri: detail.uri,
                    reason: error.to_string(),
                    request_fingerprint: None,
                    unordered_json: None,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;
