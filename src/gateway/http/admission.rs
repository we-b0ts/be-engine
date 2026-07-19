use chrono::{DateTime, Utc};
use hyper::Uri;
use serde::Serialize;
use tracing::{info, warn};
use uuid::Uuid;

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
            let admission = CaseAdmissionRecord {
                timestamp: Utc::now(),
                case_id: case.id,
                rule_name: case.rule_name.clone(),
                uri_group: case.uri_group.clone(),
                case_pattern: case_pattern.to_string(),
                uri: uri.to_string(),
                upstream: upstream_base.to_string(),
                upstream_pid: process.as_ref().map(|process| process.pid),
            };
            if let Err(err) = state
                .recorder()
                .write_case_json(case, "admission.json", &admission)
                .await
            {
                warn!(
                    error = %err,
                    case_id = %case.id,
                    "failed to persist HTTP gateway case admission"
                );
                return None;
            }
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

#[derive(Serialize)]
struct CaseAdmissionRecord {
    timestamp: DateTime<Utc>,
    case_id: Uuid,
    rule_name: String,
    uri_group: Option<String>,
    case_pattern: String,
    uri: String,
    upstream: String,
    upstream_pid: Option<u32>,
}

fn active_case_rejection_reason(reason: ActiveCaseRejection) -> &'static str {
    match reason {
        ActiveCaseRejection::NotReady => "not_ready",
        ActiveCaseRejection::Busy => "busy",
    }
}
