//! Group response differences and materialize representative observations.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::primary_protocol::assertion::{ResponseDifference, ResponseDifferenceKind};

use super::super::model::{CaseExecution, ResponseAssertionSummary};
use super::observation::request_correlated_header_observation;
use super::{
    E2eFailureCluster, E2eRepresentativeDifference, E2eResponseDifferenceDiagnosis,
    E2eValueObservation, E2eValuePresence, RESPONSE_AVAILABILITY_POINTER,
    response_observation_with_status, response_pointer_pattern,
};

const MAX_FAILURE_CLUSTERS: usize = 20;

pub(crate) fn response_differences<'a>(
    cases: impl Iterator<Item = &'a CaseExecution>,
    mut report_cases: impl FnMut(&E2eFailureCluster, BTreeSet<String>),
) -> E2eResponseDifferenceDiagnosis {
    let mut clusters =
        BTreeMap::<(String, ResponseDifferenceKind), FailureClusterAccumulator>::new();
    let mut total_differences = 0usize;
    let mut indexed_differences = 0usize;
    for case in cases {
        if let Some(assertion) = &case.response_assertion {
            total_differences = total_differences.saturating_add(assertion.difference_count);
            let differences = indexed_response_differences(assertion);
            indexed_differences = indexed_differences.saturating_add(differences.len());
            for difference in differences {
                index_response_difference(
                    &mut clusters,
                    &case.case_id,
                    &difference.pointer,
                    difference.kind,
                );
            }
        } else if case.assertion_passed == Some(false) {
            total_differences = total_differences.saturating_add(1);
            indexed_differences = indexed_differences.saturating_add(1);
            index_response_difference(
                &mut clusters,
                &case.case_id,
                RESPONSE_AVAILABILITY_POINTER,
                ResponseDifferenceKind::ResponseUnavailable,
            );
        }
    }
    let mut failure_clusters = clusters
        .into_iter()
        .map(|((pointer_pattern, difference_kind), cluster)| {
            (
                E2eFailureCluster {
                    pointer_pattern,
                    difference_kind,
                    affected_cases: cluster.affected_cases.len(),
                    occurrences: cluster.occurrences,
                    representative_case_id: cluster.representative_case_id,
                    representative_pointer: cluster.representative_pointer,
                },
                cluster.affected_cases,
            )
        })
        .collect::<Vec<_>>();
    failure_clusters.sort_by(|(left, _), (right, _)| {
        // A different primary status explains why its expected body and
        // asynchronous work may be absent; show it before derivative fields.
        (left.difference_kind != ResponseDifferenceKind::StatusMismatch)
            .cmp(&(right.difference_kind != ResponseDifferenceKind::StatusMismatch))
            .then_with(|| right.affected_cases.cmp(&left.affected_cases))
            .then_with(|| right.occurrences.cmp(&left.occurrences))
            .then_with(|| left.pointer_pattern.cmp(&right.pointer_pattern))
            .then_with(|| left.difference_kind.cmp(&right.difference_kind))
    });
    let omitted_failure_clusters = failure_clusters.len().saturating_sub(MAX_FAILURE_CLUSTERS);
    failure_clusters.truncate(MAX_FAILURE_CLUSTERS);
    E2eResponseDifferenceDiagnosis {
        total_differences,
        indexed_differences,
        omitted_differences: total_differences.saturating_sub(indexed_differences),
        failure_clusters: failure_clusters
            .into_iter()
            .map(|(cluster, cases)| {
                report_cases(&cluster, cases);
                cluster
            })
            .collect(),
        omitted_failure_clusters,
    }
}

pub(crate) fn representative_difference(
    case: &CaseExecution,
    cluster: &E2eFailureCluster,
    published_path: impl FnOnce(&Path) -> PathBuf,
) -> Option<E2eRepresentativeDifference> {
    if cluster.difference_kind == ResponseDifferenceKind::ResponseUnavailable {
        Some(E2eRepresentativeDifference {
            case_id: cluster.representative_case_id.clone(),
            pointer: cluster.representative_pointer.clone(),
            difference_kind: cluster.difference_kind,
            gateway_protocol: None,
            body_codec: None,
            body_diagnosis: None,
            unavailable_reason: case.response_unavailable_reason,
            expected: E2eValueObservation {
                presence: E2eValuePresence::Present,
                value: None,
                jwt_candidate: false,
            },
            actual: E2eValueObservation {
                presence: E2eValuePresence::Unavailable,
                value: None,
                jwt_candidate: false,
            },
        })
    } else {
        let assertion = case.response_assertion.as_ref()?;
        let actual_response = published_path(&assertion.actual_response);
        let (expected, actual) = if cluster.representative_pointer == "$headers/x-request-id" {
            (
                request_correlated_header_observation(
                    &assertion.expected_response,
                    &assertion.request,
                    "headers",
                    "x-request-id",
                ),
                request_correlated_header_observation(
                    &actual_response,
                    &actual_response,
                    "request_headers",
                    "x-request-id",
                ),
            )
        } else {
            (
                response_observation_with_status(
                    &assertion.expected_response,
                    &cluster.representative_pointer,
                    representative_status(assertion, cluster, true),
                ),
                response_observation_with_status(
                    &actual_response,
                    &cluster.representative_pointer,
                    representative_status(assertion, cluster, false),
                ),
            )
        };
        Some(E2eRepresentativeDifference {
            case_id: cluster.representative_case_id.clone(),
            pointer: cluster.representative_pointer.clone(),
            difference_kind: cluster.difference_kind,
            gateway_protocol: Some(assertion.gateway_protocol),
            body_codec: Some(assertion.body_codec),
            body_diagnosis: assertion.body_diagnosis.clone(),
            unavailable_reason: None,
            expected,
            actual,
        })
    }
}

struct FailureClusterAccumulator {
    affected_cases: BTreeSet<String>,
    occurrences: usize,
    representative_case_id: String,
    representative_pointer: String,
}

fn index_response_difference(
    clusters: &mut BTreeMap<(String, ResponseDifferenceKind), FailureClusterAccumulator>,
    case_id: &str,
    pointer: &str,
    kind: ResponseDifferenceKind,
) {
    let key = (response_pointer_pattern(pointer), kind);
    let cluster = clusters
        .entry(key)
        .or_insert_with(|| FailureClusterAccumulator {
            affected_cases: BTreeSet::new(),
            occurrences: 0,
            representative_case_id: case_id.to_string(),
            representative_pointer: pointer.to_string(),
        });
    cluster.affected_cases.insert(case_id.to_string());
    cluster.occurrences = cluster.occurrences.saturating_add(1);
}

fn indexed_response_differences(assertion: &ResponseAssertionSummary) -> &[ResponseDifference] {
    if assertion.difference_index.is_empty() {
        assertion.representative_difference.as_slice()
    } else {
        &assertion.difference_index
    }
}

fn representative_status(
    assertion: &ResponseAssertionSummary,
    cluster: &E2eFailureCluster,
    expected: bool,
) -> Option<u16> {
    indexed_response_differences(assertion)
        .iter()
        .find(|difference| {
            difference.pointer == cluster.representative_pointer
                && difference.kind == cluster.difference_kind
        })
        .and_then(|difference| {
            if expected {
                difference.expected_status
            } else {
                difference.actual_status
            }
        })
}
