//! Explicit acceptance scope does not change session closure or batch evidence.
use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) enum FinalizationScope {
    WholeSession,
    SelectedCases,
}

impl FinalizationScope {
    pub(crate) fn command(self) -> &'static str {
        match self {
            Self::WholeSession => "finalize",
            Self::SelectedCases => "finalize_cases",
        }
    }

    pub(super) fn from_command(command: &str) -> Self {
        if command == Self::SelectedCases.command() {
            Self::SelectedCases
        } else {
            Self::WholeSession
        }
    }

    pub(super) fn is_dirty(self, report: &ReplayReport) -> bool {
        match self {
            Self::WholeSession => report_is_dirty(report),
            Self::SelectedCases => {
                let value = serde_json::to_value(report).expect("Replay report must serialize");
                // Reuse the same Case boundary as aggregation and API evidence.
                // Startup/run-owned debt stays in the unchanged batch receipt.
                crate::replay::report::report_has_case_dirty_events(&value)
                    || !report.dependency_pre_matches.is_empty()
                    || report.replay_policy.as_ref().is_some_and(|policy| {
                        !policy.unused_applicable_dependency_rule_ids.is_empty()
                    })
            }
        }
    }
}
