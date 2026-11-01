//! Chronological input admission on one startup-owned Target process.
use anyhow::Result;

use super::{
    case_progress,
    execute::{CaseExecutionRuntime, execute_case},
    model::{ActiveRunState, ResolvedProjectConfig, RunLayout},
};

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
        execute_case(
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
    }

    Ok(())
}

#[cfg(test)]
mod tests;
