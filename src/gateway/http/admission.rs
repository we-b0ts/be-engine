use hyper::Uri;
use tracing::info;

use super::transport::upstream_socket_addr;
use crate::process_lookup::{lookup_listening_process, process_label};
use crate::recorder::CaseContext;
use crate::{ActiveCaseGuard, ActiveCaseRejection, AppState};

pub(super) async fn try_admit_case(
    state: &AppState,
    case: &CaseContext,
    case_pattern: &str,
    max_cases: usize,
    upstream_base: &str,
    uri: &Uri,
) -> Option<ActiveCaseGuard> {
    let published_cases = state.recorder().published_case_count(case).await;
    if published_cases >= max_cases {
        info!(
            reason = "case_limit_reached",
            rule = %case.rule_name,
            case_pattern,
            published_cases,
            max_cases,
            uri = %uri,
            "HTTP gateway matched request sent to fallback"
        );
        return None;
    }

    let process = upstream_socket_addr(upstream_base).and_then(lookup_listening_process);
    match state.try_register_active_case(case.clone(), process.as_ref().map(|process| process.pid))
    {
        Ok(guard) => {
            match &process {
                Some(process) => {
                    info!(
                        case_id = %case.id,
                        rule = %case.rule_name,
                        case_pattern,
                        upstream = %upstream_base,
                        process = %process_label(process),
                        "registered active HTTP gateway case"
                    );
                }
                None => {
                    info!(
                        case_id = %case.id,
                        rule = %case.rule_name,
                        case_pattern,
                        upstream = %upstream_base,
                        "registered active HTTP gateway case without upstream process match"
                    );
                }
            }
            Some(guard)
        }
        Err(reason) => {
            info!(
                reason = active_case_rejection_reason(reason),
                rule = %case.rule_name,
                case_pattern,
                uri = %uri,
                "HTTP gateway matched request sent to fallback"
            );
            None
        }
    }
}

fn active_case_rejection_reason(reason: ActiveCaseRejection) -> &'static str {
    match reason {
        ActiveCaseRejection::NotReady => "not_ready",
        ActiveCaseRejection::Busy => "busy",
    }
}
