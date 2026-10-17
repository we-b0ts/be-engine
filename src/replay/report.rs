use super::*;

pub(crate) mod aggregate;
#[cfg(test)]
mod aggregate_tests;
mod background_overlay;
pub(super) mod command;
mod dependency_evidence;
pub(in crate::replay) mod global_evidence;
mod model;
mod success;
mod writer;
#[cfg(test)]
mod writer_tests;

#[cfg(test)]
pub(super) use dependency_evidence::report_has_case_dirty_events;
pub(crate) use dependency_evidence::{build_dependency_evidence, dependency_evidence_path};
pub(crate) use global_evidence::stage_global_evidence;

pub(crate) use background_overlay::{
    BackgroundReclassification, parse_background_dependency_evidence,
    reclassify_background_dependencies, source_owned_match,
};
pub(crate) use dependency_evidence::{
    ReplayDependencyCluster, ReplayDependencyDifference, ReplayDependencyEndpoint,
    ReplayDependencyObservation, ReplayDependencyRepresentative, ReplayDependencyTargetMatch,
    read_dependency_evidence,
};
pub(super) use model::*;
pub(super) use success::{
    SUCCESS_DETAIL_LIMIT, SUCCESS_DETAIL_SCOPE, SuccessDetailBudget, push_success_detail,
};
#[cfg(test)]
pub(super) use writer::write_report_snapshot;
pub(super) use writer::{clear_report_artifacts, write_final_report_value};
