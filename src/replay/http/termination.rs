//! Reserve zero-response HTTP exchanges until the observed client termination.
use super::super::{ReplayExchangeStatus, ReplayExchangeTiming};
use super::*;
use tokio::time::Instant;

pub(super) struct PendingHttpTermination {
    pub(super) detail: MatchedHttpExchangeReport,
    pub(super) timing: ReplayExchangeTiming,
    pub(super) started: Instant,
}

impl PendingHttpTermination {
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
        }
    }
}

pub(super) fn validate_record(record: &RecordedHttpExchange) -> Result<()> {
    if record.outcome == crate::DependencyExchangeOutcome::NoResponse {
        return Err(anyhow!(
            "HTTP does not support a protocol-level no_response outcome"
        ));
    }
    if !record.outcome.is_client_terminated() {
        return Ok(());
    }
    anyhow::ensure!(
        record.error.is_none(),
        "HTTP client termination contains an upstream/capture error"
    );
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
        let detail = pending.detail;
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
