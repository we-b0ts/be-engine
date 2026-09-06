use serde_json::{Value, json};

use super::{ActiveRunState, RunLayout, published_path};
use crate::replay::report::read_dependency_evidence;

pub(super) fn diagnosis(layout: &RunLayout, state: &ActiveRunState) -> Option<Value> {
    let failed = state
        .cases
        .iter()
        .any(|case| case.assertion_passed == Some(false));
    let dirty = state
        .cases
        .iter()
        .any(|case| case.replay_clean == Some(false))
        || (state.aggregate_complete && !state.aggregate_clean);
    if !failed && !dirty {
        return None;
    }
    let evidence = read_dependency_evidence(&published_path(layout, &state.replay_report)).ok()?;
    projection(evidence.egress_rejections, evidence.omitted_egress_cases)
}

pub(crate) fn projection(
    samples: Vec<crate::ReplayEgressRejections>,
    omitted: usize,
) -> Option<Value> {
    if samples.is_empty() {
        return None;
    }
    let rejected_packets: u64 = samples
        .iter()
        .filter_map(|sample| sample.rejected_packets)
        .fold(0, u64::saturating_add);
    let unavailable_cases = samples
        .iter()
        .filter(|sample| sample.rejected_packets.is_none())
        .count();
    if rejected_packets == 0 && unavailable_cases == 0 && omitted == 0 {
        return None;
    }
    Some(json!({
        "observed_by":"firewall_reject_counter", "samples":samples,
        "rejected_packets_in_samples":rejected_packets,"unavailable_cases":unavailable_cases,
        "omitted_cases":omitted,
        "summary": if rejected_packets > 0 { "The target UID had rejected outbound packets during case execution. Investigate dependency access and consider recorder response rewrite pointers when source code proves an upstream JSON URL." } else { "Firewall rejection counts are unavailable or incomplete; absence of rejection is not established." },
        "does_not_prove":"Counts include retries and same-UID background traffic. They do not identify an IP, its origin, individual call count, exact rejection times, or the cause of response/dependency differences."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(count: Option<u64>) -> crate::ReplayEgressRejections {
        crate::ReplayEgressRejections {
            case_id: "case".into(),
            observed_from: chrono::Utc::now(),
            observed_until: chrono::Utc::now(),
            rejected_packets: count,
            unavailable_reason: count
                .is_none()
                .then(|| "counter_read_failed_or_rules_reset".into()),
        }
    }
    #[test]
    fn zero_is_quiet_and_missing_is_not_zero() {
        assert!(projection(vec![sample(Some(0))], 0).is_none());
        let present = projection(vec![sample(Some(3))], 0).unwrap();
        assert_eq!(present["rejected_packets_in_samples"], 3);
        assert!(present.get("destination_ip").is_none());
        assert_eq!(
            projection(vec![sample(None)], 0).unwrap()["unavailable_cases"],
            1
        );
    }

    #[test]
    fn published_rejections_are_only_projected_for_response_failures_or_dirty_dependencies() {
        use crate::case_group::{CanonicalCase, CanonicalCaseGroup, CaseGroupInventory};
        let temp = tempfile::tempdir().unwrap();
        let layout = RunLayout {
            target_root: temp.path().into(),
            run_key: "run".into(),
            case_source: temp.path().join("cases"),
            progress_path: temp.path().join("progress"),
            legacy_progress_path: temp.path().join("legacy"),
            internal_root: temp.path().join("internal"),
            current_path: temp.path().join("current"),
            run_root: temp.path().join("run"),
            index_path: temp.path().join("index"),
            group_index_path: temp.path().join("groups"),
            active_dir: temp.path().join("active"),
            latest_dir: temp.path().join("latest"),
        };
        let inventory = CaseGroupInventory {
            case_source: layout.case_source.clone(),
            source_revision: "source".into(),
            case_inventory_id: "inventory".into(),
            groups: vec![CanonicalCaseGroup {
                group_id: "GET /api".into(),
                method: "GET".into(),
                source_route: "/api".into(),
                pattern: None,
                case_inventory_id: "inventory".into(),
                cases: vec![CanonicalCase {
                    case_id: "case".into(),
                    case_dir: layout.case_source.join("case"),
                    recorded_at: None,
                }],
            }],
        };
        let mut state = ActiveRunState::new("run".into(), 1, &inventory, &layout.active_dir);
        state.replay_finalized = true;
        state.aggregate_complete = true;
        state.aggregate_clean = true;
        state.cases[0].assertion_passed = Some(true);
        state.cases[0].replay_clean = Some(true);
        let sidecar = published_path(&layout, &state.replay_report)
            .with_file_name("replay-report-dependency-evidence.json");
        std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        std::fs::write(
            sidecar,
            json!({
                "version":1, "case_event_counts":{}, "clusters":[], "omitted_clusters":0,
                "egress_rejections":[sample(Some(3))], "omitted_egress_cases":0,
            })
            .to_string(),
        )
        .unwrap();

        assert!(diagnosis(&layout, &state).is_none());
        assert_eq!(
            super::super::verification_gates(&state).dependencies,
            super::super::E2eDependencyGate::Clean
        );
        state.cases[0].assertion_passed = Some(false);
        assert_eq!(
            diagnosis(&layout, &state).unwrap()["rejected_packets_in_samples"],
            3
        );
        state.cases[0].assertion_passed = Some(true);
        state.cases[0].replay_clean = Some(false);
        assert!(diagnosis(&layout, &state).is_some());
        state.cases[0].replay_clean = Some(true);
        state.aggregate_clean = false;
        assert!(diagnosis(&layout, &state).is_some());
        state.aggregate_complete = false;
        assert!(diagnosis(&layout, &state).is_none());
    }
}
