use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::model::ActiveRunState;
use crate::recorder::load_pre_readiness_traffic_summary;
use crate::replay::report::{
    ReplayDependencyCluster, ReplayDependencyDifference, ReplayDependencyEndpoint,
    ReplayDependencyObservation, ReplayDependencyRepresentative, read_dependency_evidence,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eDirtyCounts {
    pub complete: bool,
    pub dirty: bool,
    pub case_event_counts: BTreeMap<String, BTreeMap<String, usize>>,
    pub clusters: Vec<E2eDirtyCluster>,
    pub omitted_clusters: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_pre_readiness: Option<E2eSourcePreReadiness>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eDirtyCluster {
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<E2eDependencyEndpoint>,
    pub scope: String,
    pub reason: String,
    pub count: usize,
    pub case_count: usize,
    pub case_ids: Vec<String>,
    pub omitted_case_ids: usize,
    pub operations: BTreeMap<String, usize>,
    pub omitted_operations: usize,
    pub source_pre_readiness_interactions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative: Option<E2eDependencyRepresentative>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eDependencyEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eDependencyRepresentative {
    pub case_id: String,
    pub case_dir: PathBuf,
    pub difference: E2eDependencyDifference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eDependencyDifference {
    pub kind: String,
    pub expected: E2eDependencyObservation,
    pub actual: E2eDependencyObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eDependencyObservation {
    pub presence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eSourcePreReadiness {
    pub phase: String,
    pub role: String,
    pub interaction_count: usize,
    pub endpoints: Vec<E2eSourcePreReadinessEndpoint>,
    pub unresolved_interactions: usize,
    pub omitted_interactions: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eSourcePreReadinessEndpoint {
    pub endpoint: String,
    pub interaction_count: usize,
    pub protocols: BTreeMap<String, usize>,
}

pub(super) fn build(state: &ActiveRunState, complete: bool, dirty: bool) -> Result<E2eDirtyCounts> {
    let evidence = read_dependency_evidence(&state.replay_report)?;
    let case_dirs = state
        .cases
        .iter()
        .map(|case| {
            let case_dir = std::fs::canonicalize(&case.case_dir).with_context(|| {
                format!(
                    "failed to resolve recorded case {}",
                    case.case_dir.display()
                )
            })?;
            Ok((case.case_id.clone(), case_dir))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let source_pre_readiness = source_pre_readiness(state)?;
    let pre_readiness_counts = source_pre_readiness
        .iter()
        .flat_map(|summary| &summary.endpoints)
        .map(|endpoint| (endpoint.endpoint.clone(), endpoint.interaction_count))
        .collect::<BTreeMap<_, _>>();
    let clusters = evidence
        .clusters
        .into_iter()
        .map(|cluster| enrich_cluster(cluster, &case_dirs, &pre_readiness_counts))
        .collect::<Result<Vec<_>>>()?;
    Ok(E2eDirtyCounts {
        complete,
        dirty,
        case_event_counts: evidence.case_event_counts,
        clusters,
        omitted_clusters: evidence.omitted_clusters,
        source_pre_readiness,
    })
}

fn source_pre_readiness(state: &ActiveRunState) -> Result<Option<E2eSourcePreReadiness>> {
    Ok(
        load_pre_readiness_traffic_summary(&state.case_source)?.map(|value| {
            E2eSourcePreReadiness {
                phase: value.phase,
                role: "reference_only".to_string(),
                interaction_count: value.data_interactions,
                endpoints: value
                    .endpoints
                    .into_iter()
                    .map(|endpoint| E2eSourcePreReadinessEndpoint {
                        endpoint: endpoint.endpoint,
                        interaction_count: endpoint.interaction_count,
                        protocols: endpoint.protocols,
                    })
                    .collect(),
                unresolved_interactions: value.unresolved_interactions,
                omitted_interactions: value.omitted_interactions,
                truncated: value.truncated,
            }
        }),
    )
}

fn enrich_cluster(
    cluster: ReplayDependencyCluster,
    case_dirs: &BTreeMap<String, PathBuf>,
    pre_readiness_counts: &BTreeMap<String, usize>,
) -> Result<E2eDirtyCluster> {
    let endpoint = cluster.endpoint.map(endpoint_from_replay);
    let source_pre_readiness_interactions = endpoint
        .as_ref()
        .and_then(|value| pre_readiness_counts.get(&endpoint_key(value)))
        .copied()
        .unwrap_or_default();
    let representative = cluster
        .representative
        .map(|value| representative_from_replay(value, case_dirs))
        .transpose()?;
    Ok(E2eDirtyCluster {
        protocol: cluster.protocol,
        endpoint,
        scope: "case".to_string(),
        reason: cluster.reason,
        count: cluster.count,
        case_count: cluster.case_count,
        case_ids: cluster.case_ids,
        omitted_case_ids: cluster.omitted_case_ids,
        operations: cluster.operations,
        omitted_operations: cluster.omitted_operations,
        source_pre_readiness_interactions,
        representative,
    })
}

fn representative_from_replay(
    representative: ReplayDependencyRepresentative,
    case_dirs: &BTreeMap<String, PathBuf>,
) -> Result<E2eDependencyRepresentative> {
    let case_dir = case_dirs
        .get(&representative.case_id)
        .cloned()
        .with_context(|| {
            format!(
                "dirty dependency references unknown case {:?}",
                representative.case_id
            )
        })?;
    Ok(E2eDependencyRepresentative {
        case_id: representative.case_id,
        case_dir,
        difference: difference_from_replay(representative.difference),
    })
}

fn endpoint_from_replay(endpoint: ReplayDependencyEndpoint) -> E2eDependencyEndpoint {
    E2eDependencyEndpoint {
        host: endpoint.host,
        port: endpoint.port,
    }
}

fn difference_from_replay(difference: ReplayDependencyDifference) -> E2eDependencyDifference {
    E2eDependencyDifference {
        kind: difference.kind,
        expected: observation_from_replay(difference.expected),
        actual: observation_from_replay(difference.actual),
    }
}

fn observation_from_replay(observation: ReplayDependencyObservation) -> E2eDependencyObservation {
    E2eDependencyObservation {
        presence: observation.presence,
        signature: observation.signature,
    }
}

fn endpoint_key(endpoint: &E2eDependencyEndpoint) -> String {
    format!("{}:{}", endpoint.host, endpoint.port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::report::{
        ReplayDependencyDifference, ReplayDependencyObservation, ReplayDependencyRepresentative,
    };

    #[test]
    fn enriches_case_cluster_with_exact_case_dir_and_startup_reference_count() {
        let cluster = ReplayDependencyCluster {
            protocol: "memcached".to_string(),
            endpoint: Some(ReplayDependencyEndpoint {
                host: "cache.internal".to_string(),
                port: 11211,
            }),
            reason: "unused_recorded".to_string(),
            count: 2,
            case_count: 1,
            case_ids: vec!["case-a".to_string()],
            omitted_case_ids: 0,
            operations: BTreeMap::from([("get".to_string(), 2)]),
            omitted_operations: 0,
            representative: Some(ReplayDependencyRepresentative {
                case_id: "case-a".to_string(),
                difference: ReplayDependencyDifference {
                    kind: "unused_recorded".to_string(),
                    expected: ReplayDependencyObservation {
                        presence: "present".to_string(),
                        signature: Some(serde_json::json!({"command":"get"})),
                    },
                    actual: ReplayDependencyObservation {
                        presence: "missing".to_string(),
                        signature: None,
                    },
                },
            }),
        };
        let case_dirs =
            BTreeMap::from([("case-a".to_string(), PathBuf::from("/recording/case-a"))]);
        let startup = BTreeMap::from([("cache.internal:11211".to_string(), 9)]);

        let cluster = enrich_cluster(cluster, &case_dirs, &startup).unwrap();

        assert_eq!(cluster.scope, "case");
        assert_eq!(cluster.source_pre_readiness_interactions, 9);
        let representative = cluster.representative.unwrap();
        assert_eq!(representative.case_id, "case-a");
        assert_eq!(representative.case_dir, PathBuf::from("/recording/case-a"));
        assert_eq!(representative.difference.kind, "unused_recorded");
    }
}
