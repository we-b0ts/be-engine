//! Application report queries compose the installed native evidence codecs.
use serde_json::Value;

pub fn build_dependency_evidence(
    report: &Value,
) -> crate::replay::report::ReplayDependencyEvidence {
    crate::replay::report::build_dependency_evidence(
        report,
        crate::protocols::default_providers().report_codecs(),
    )
}

pub fn report_has_case_dirty_events(report: &Value) -> bool {
    crate::replay::report::report_has_case_dirty_events(
        report,
        crate::protocols::default_providers().report_codecs(),
    )
}
