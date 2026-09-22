use super::*;

pub(crate) mod aggregate;
#[cfg(test)]
mod aggregate_tests;
mod background_overlay;
pub(super) mod command;
mod dependency_evidence;
mod model;
mod success;
mod writer;
#[cfg(test)]
mod writer_tests;

pub(crate) use background_overlay::{
    BackgroundReclassification, reclassify_background_dependencies,
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
