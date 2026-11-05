use super::*;

pub(in crate::replay) const MYSQL_TRANSACTION_SEMANTICS: &str = "first_write_through_end_v1";

pub(crate) mod aggregate;
#[cfg(test)]
mod aggregate_tests;
mod background_overlay;
pub(super) mod command;
mod dependency_evidence;
pub(in crate::replay) mod global_evidence;
mod model;
mod sql_summary;
mod success;
pub(crate) mod unused_source;
mod writer;
#[cfg(test)]
mod writer_tests;

pub(crate) use dependency_evidence::report_has_case_dirty_events;
pub(crate) use dependency_evidence::{build_dependency_evidence, dependency_evidence_path};
pub(crate) use global_evidence::preparation::prewarm as prewarm_global_report;
pub(crate) use global_evidence::stage_global_evidence;

#[cfg(test)]
pub(crate) use background_overlay::reclassify_background_dependencies;
pub(crate) use background_overlay::{parse_background_dependency_evidence, source_owned_match};
pub(crate) use dependency_evidence::{
    ReplayDependencyCluster, ReplayDependencyDifference, ReplayDependencyEndpoint,
    ReplayDependencyObservation, ReplayDependencyRepresentative, ReplayDependencyTargetMatch,
    read_dependency_evidence,
};
pub(super) use model::*;
pub(super) use sql_summary::SqlSummary;
pub(super) use success::{
    SUCCESS_DETAIL_LIMIT, SUCCESS_DETAIL_SCOPE, SuccessDetailBudget, push_success_detail,
};
#[cfg(test)]
pub(super) use writer::write_report_snapshot;
pub(super) use writer::{clear_report_artifacts, write_final_report_value};
