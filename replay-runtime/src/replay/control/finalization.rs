//! Explicit acceptance scope does not change session closure or batch evidence.
use super::*;

pub(super) trait FinalizationCheck {
    fn is_dirty<S: traffic_replay::report::SessionSnapshot>(
        &self,
        report: &ReplayReport<S>,
        codecs: &traffic_protocol::report::CodecRegistry,
    ) -> bool;
}
impl FinalizationCheck for FinalizationScope {
    fn is_dirty<S: traffic_replay::report::SessionSnapshot>(
        &self,
        report: &ReplayReport<S>,
        codecs: &traffic_protocol::report::CodecRegistry,
    ) -> bool {
        match self {
            Self::WholeSession => report_is_dirty(report),
            Self::SelectedCases => {
                let value = serde_json::to_value(report).expect("Replay report must serialize");
                // Reuse the same Case boundary as aggregation and API evidence.
                // Startup/run-owned debt stays in the unchanged batch receipt.
                crate::replay::report::report_has_case_dirty_events(&value, codecs)
                    || !report.dependency_pre_matches.is_empty()
                    || report.replay_policy.as_ref().is_some_and(|policy| {
                        !policy.unused_applicable_dependency_rule_ids.is_empty()
                    })
            }
        }
    }
}

pub use traffic_engine_replay::replay::control::FinalizationScope;
