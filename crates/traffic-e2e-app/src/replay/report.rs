use super::*;

pub(crate) mod command;
mod dependency_evidence;
pub(crate) mod global_evidence;
mod model;
mod success;
pub(crate) mod unused_source;
mod writer;
#[cfg(test)]
mod writer_tests;

pub(crate) use dependency_evidence::report_has_case_dirty_events;
pub(crate) use dependency_evidence::{build_dependency_evidence, dependency_evidence_path};

pub(crate) use dependency_evidence::{
    ReplayDependencyCluster, ReplayDependencyDifference, ReplayDependencyEndpoint,
    ReplayDependencyEvidence, ReplayDependencyObservation, ReplayDependencyRepresentative,
    ReplayDependencyTargetMatch, read_dependency_evidence,
};
pub(crate) use model::*;
pub(crate) use success::{SUCCESS_DETAIL_LIMIT, SUCCESS_DETAIL_SCOPE};
#[cfg(test)]
pub(crate) use writer::write_report_snapshot;
pub(crate) use writer::{clear_report_artifacts, write_final_report_value};
