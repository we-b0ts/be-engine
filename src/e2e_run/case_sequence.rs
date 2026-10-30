//! Chronological input admission on one startup-owned Target process.
use anyhow::Result;
use serde_json::Value;

use super::{
    case_progress,
    execute::{CaseExecutionRuntime, execute_case},
    model::{ActiveRunState, ResolvedProjectConfig, RunLayout},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Continuation {
    ReuseTarget,
    StopTarget,
}

impl Continuation {
    pub(super) fn after_response(request: &[u8], response: &Result<Vec<u8>>) -> Self {
        let request = serde_json::from_slice::<Value>(request).ok();
        let session = request
            .as_ref()
            .and_then(|r| r.pointer("/interaction/protocol"))
            .and_then(Value::as_str)
            .is_some_and(|p| matches!(p, "socket_io" | "web_socket"));
        if !session {
            return Self::ReuseTarget;
        }
        let closed = response
            .as_ref()
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            .is_some_and(|r| r.pointer("/interaction/end/clean") == Some(&Value::Bool(true)));
        if closed {
            Self::ReuseTarget
        } else {
            Self::StopTarget
        }
    }
}

pub(super) async fn execute(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    state: &mut ActiveRunState,
    case_runtime: &CaseExecutionRuntime,
) -> Result<()> {
    let total_cases = state.cases.len();
    let mut failure_limit =
        super::failure_limit::ApiFailureLimit::new(config.max_failed_cases_per_api);
    case_progress::log_start(total_cases);
    for (position, case) in state.cases.clone().into_iter().enumerate() {
        if !failure_limit.should_execute(&case.group_id) {
            continue;
        }
        let continuation = execute_case(
            config,
            layout,
            state,
            position,
            &case.case_id,
            &case.case_dir,
            case_runtime,
        )
        .await?;
        case_progress::log_completion(position + 1, total_cases);
        if failure_limit.observe(&case.group_id, state.cases[position].status) {
            state.push_error(format!(
                "API {:?} stopped after reaching the configured failure limit of {} case(s)",
                case.group_id, config.max_failed_cases_per_api
            ));
        }
        if continuation == Continuation::StopTarget {
            state.push_error(format!(
                "case {} did not cleanly close its live session; stopped the attempt before admitting later inputs to a Target with unconfirmed teardown",
                case.case_id
            ));
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
