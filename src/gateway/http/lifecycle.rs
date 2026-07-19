use std::future::Future;

use hyper::{Response, StatusCode};
use tracing::warn;
use uuid::Uuid;

use super::transport::{GatewayBody, simple_response};
use crate::recorder::http::case::CaseInvalidation;
use crate::{ActiveCaseGuard, AppState};

pub(super) async fn run_matched_request<F>(
    state: AppState,
    case_id: Uuid,
    active_case_guard: ActiveCaseGuard,
    request: F,
) -> Response<GatewayBody>
where
    F: Future<Output = Response<GatewayBody>> + Send + 'static,
{
    let mut downstream = DownstreamRequest::new(state, case_id);
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
}

impl DownstreamRequest {
    fn new(state: AppState, case_id: Uuid) -> Self {
        Self {
            state,
            case_id,
            completed: false,
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
        let invalidation = CaseInvalidation::new(
            "downstream_disconnected",
            "downstream connection ended before the matched upstream request completed",
        );
        if self
            .state
            .invalidate_active_case(self.case_id, invalidation)
            .is_some()
        {
            warn!(
                case_id = %self.case_id,
                "downstream disconnected; matched request will continue to preserve dependency isolation"
            );
        }
    }
}
