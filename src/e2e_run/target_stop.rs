//! Preserve the recorded Source process boundary before releasing its last Case.
use super::model::{ActiveRunState, RunLayout};
use anyhow::{Result, ensure};

pub(super) async fn finish(
    layout: &RunLayout,
    state: &mut ActiveRunState,
    index: usize,
    case: &str,
) -> Result<serde_json::Value> {
    // A managed Source shutdown ends its recording run. Chronological execution
    // cannot reuse that process for later cases or invent another bootstrap.
    require_last_case(index, state.cases.len())?;
    super::runtime::control(state, "prepare_end", Some(case), false, false).await?;
    super::runtime::stop_target_at_case_boundary(layout, state).await?;
    super::runtime::control(state, "end_stopped", Some(case), true, false).await
}

fn require_last_case(index: usize, count: usize) -> Result<()> {
    ensure!(
        index.checked_add(1) == Some(count),
        "Source shutdown is a terminal recording-session boundary; later selected Cases require fresh recording with explicit session boundaries"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn source_stop_ends_the_recorded_session_without_reusing_target_or_bootstrap() {
        assert!(super::require_last_case(0, 1).is_ok());
        assert!(super::require_last_case(3, 4).is_ok());
        assert!(super::require_last_case(0, 2).is_err());
        assert!(super::require_last_case(usize::MAX, 0).is_err());
    }
}
