use std::future::Future;
use std::time::Instant;

use hyper::{Response, StatusCode};
use tokio::sync::oneshot;
use tracing::warn;
use uuid::Uuid;

use super::transport::{GatewayBody, simple_response};
use crate::recorder::{CaseInvalidation, CaseInvalidationContext};
use crate::{ActiveCaseGuard, AppState};

pub(super) async fn run_matched_request<F>(
    state: AppState,
    case_id: Uuid,
    active_case_guard: std::sync::Arc<ActiveCaseGuard>,
    started: Instant,
    mut timeout_response: oneshot::Receiver<()>,
    request: F,
) -> Response<GatewayBody>
where
    F: Future<Output = Response<GatewayBody>> + Send + 'static,
{
    let timeout_ms = state.config().http_gateway.request_timeout_ms;
    let mut downstream = DownstreamRequest::new(state, case_id, started);
    let mut request = tokio::spawn(async move {
        let _active_case_guard = active_case_guard;
        request.await
    });
    let result = tokio::select! {
        result = &mut request => result,
        timeout = &mut timeout_response => {
            if timeout.is_ok() {
                downstream.complete();
                let mut response = simple_response(StatusCode::GATEWAY_TIMEOUT, &format!("gateway upstream request timed out after {timeout_ms} ms"));
                super::ordinary::mark_admitted_case(case_id, &mut response);
                return response;
            }
            request.await
        }
    };
    downstream.complete();

    match result {
        Ok(response) => response,
        Err(err) => {
            warn!(
                error = %err,
                %case_id,
                "matched HTTP gateway request task failed"
            );
            simple_response(
                StatusCode::BAD_GATEWAY,
                "matched HTTP gateway request task failed",
            )
        }
    }
}

struct DownstreamRequest {
    state: AppState,
    case_id: Uuid,
    completed: bool,
    started: Instant,
}

impl DownstreamRequest {
    fn new(state: AppState, case_id: Uuid, started: Instant) -> Self {
        Self {
            state,
            case_id,
            completed: false,
            started,
        }
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for DownstreamRequest {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        downstream_disconnected(&self.state, self.case_id, self.started);
    }
}

pub(super) fn downstream_disconnected(state: &AppState, case_id: Uuid, started: Instant) {
    let recorder_phase = state.recording_lifecycle_phase();
    let elapsed_ms = started.elapsed().as_millis();
    let invalidation = CaseInvalidation::new(
        "downstream_disconnected",
        "downstream connection ended before the matched upstream request completed",
    )
    .with_context(CaseInvalidationContext {
        category: "client_or_network_disconnect".to_string(),
        elapsed_ms,
        recorder_phase: recorder_phase.to_string(),
        native: Default::default(),
    });
    if state
        .invalidate_active_case(case_id, invalidation)
        .is_some()
    {
        warn!(
            %case_id,
            elapsed_ms,
            recorder_phase,
            "downstream disconnected; matched request will continue to preserve dependency isolation"
        );
    }
}
