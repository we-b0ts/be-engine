use std::future::Future;
use std::time::Instant;

use hyper::{Response, StatusCode};
use tracing::warn;
use uuid::Uuid;

use super::transport::{GatewayBody, simple_response};
use crate::recorder::http::case::{CaseInvalidation, CaseInvalidationContext};
use crate::{ActiveCaseGuard, AppState};

pub(super) async fn run_matched_request<F>(
    state: AppState,
    case_id: Uuid,
    active_case_guard: ActiveCaseGuard,
    started: Instant,
    request: F,
) -> Response<GatewayBody>
where
    F: Future<Output = Response<GatewayBody>> + Send + 'static,
{
    let mut downstream = DownstreamRequest::new(state, case_id, started);
    let request = tokio::spawn(async move {
        let _active_case_guard = active_case_guard;
        request.await
    });
    let result = request.await;
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
        let recorder_phase = self.state.recording_lifecycle_phase();
        let elapsed_ms = self.started.elapsed().as_millis();
        let invalidation = CaseInvalidation::new(
            "downstream_disconnected",
            "downstream connection ended before the matched upstream request completed",
        )
        .with_context(CaseInvalidationContext {
            category: "client_or_network_disconnect".to_string(),
            elapsed_ms,
            recorder_phase: recorder_phase.to_string(),
        });
        if self
            .state
            .invalidate_active_case(self.case_id, invalidation)
            .is_some()
        {
            warn!(
                case_id = %self.case_id,
                elapsed_ms,
                recorder_phase,
                "downstream disconnected; matched request will continue to preserve dependency isolation"
            );
        }
    }
}
