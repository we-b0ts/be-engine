use super::*;
use crate::case_group::{CanonicalCase, CanonicalCaseGroup, CaseGroupInventory};
use crate::{
    protocols::replay::report::evidence::build_dependency_evidence,
    replay::report::ReplayDependencyDifference, replay::report::ReplayDependencyObservation,
    replay::report::ReplayDependencyRepresentative, replay::report::dependency_evidence_path,
};
use serde_json::json;

fn shared_session(root: &std::path::Path, representative: &str) -> ActiveRunState {
    let case_source = root.join("recording");
    let groups = [("GET", "get-case"), ("OPTIONS", "options-case")]
        .into_iter()
        .map(|(method, case_id)| {
            let case_dir = case_source.join("apis/api-notifications").join(case_id);
            std::fs::create_dir_all(&case_dir).unwrap();
            std::fs::write(
                case_dir.join("request.json"),
                serde_json::to_vec(&json!({"method":method,"uri":"/api/notifications"})).unwrap(),
            )
            .unwrap();
            // Locating a case must not decode its assertion oracle.
            std::fs::write(case_dir.join("expected-response.json"), "not JSON").unwrap();
            CanonicalCaseGroup {
                group_id: format!("{method} /api/notifications"),
                method: method.into(),
                source_route: "/api/notifications".into(),
                pattern: None,
                case_inventory_id: "inventory".into(),
                cases: vec![CanonicalCase {
                    case_id: case_id.into(),
                    case_dir,
                    recorded_at: None,
                }],
            }
        })
        .collect();
    let inventory = CaseGroupInventory {
        case_source,
        source_revision: "source".into(),
        case_inventory_id: "inventory".into(),
        groups,
    };
    let state = ActiveRunState::new("run".into(), 1, &inventory, &root.join("runtime"));
    std::fs::create_dir_all(state.replay_report.parent().unwrap()).unwrap();
    let evidence = build_dependency_evidence(&json!({
        "unused_case_http_exchanges": (0..14).map(|_| json!({
            "case_id":representative,
            "target":{"host":"stream.example.test","port":443},
            "method":"GET","uri":"/connect","status":400
        })).collect::<Vec<_>>()
    }));
    std::fs::write(
        dependency_evidence_path(&state.replay_report),
        serde_json::to_vec(&evidence).unwrap(),
    )
    .unwrap();
    state
}

#[test]
fn method_projection_resolves_shared_session_dirty_representative() {
    let temp = tempfile::tempdir().unwrap();
    let state = shared_session(temp.path(), "get-case");
    let selected = super::super::focused_batch::project(&state, "OPTIONS /api/notifications");
    assert_eq!(selected.cases.len(), 1);
    assert_eq!(selected.cases[0].case_id, "options-case");

    let counts = build(&selected, true, true).unwrap();

    assert!(counts.complete);
    assert!(counts.dirty);
    assert_eq!(counts.case_event_counts["http"]["unused_recorded"], 14);
    assert_eq!(counts.clusters.len(), 1);
    let cluster = &counts.clusters[0];
    assert_eq!(cluster.count, 14);
    assert_eq!(cluster.case_ids, ["get-case"]);
    assert_eq!(cluster.operations["GET /connect"], 14);
    let representative = cluster.representative.as_ref().unwrap();
    assert_eq!(representative.case_id, "get-case");
    assert_eq!(representative.difference.kind, "unused_recorded");
    assert_eq!(
        representative.case_dir,
        std::fs::canonicalize(&state.cases[0].case_dir).unwrap()
    );
    // A bounded query must work without opening the full Replay report.
    assert!(!state.replay_report.exists());
}

#[test]
fn source_wire_references_survive_sidecar_and_public_dirty_projection() {
    let temp = tempfile::tempdir().unwrap();
    let state = shared_session(temp.path(), "get-case");
    let evidence = build_dependency_evidence(&json!({
        "matched_queries":[{
            "case_id":"get-case", "target_event_index":0, "index":7,
            "source":"case", "command":"COM_QUERY", "status":"resultset",
            "source_connection_id":"00000000-0000-0000-0000-000000000001",
            "source_query_sequence":2511
        }],
        "unused_case_exchanges":[{
            "case_id":"get-case", "command":"COM_QUERY", "index":8
        }]
    }));
    std::fs::write(
        dependency_evidence_path(&state.replay_report),
        serde_json::to_vec(&evidence).unwrap(),
    )
    .unwrap();
    let counts = build(&state, true, true).unwrap();
    let mut public = serde_json::to_value(&counts).unwrap();
    let matched = &mut public["clusters"][0]["representative"]["target_matches"][0];
    assert_eq!(matched["recorded_index"], 7);
    assert_eq!(matched["source_query_sequence"], 2511);
    assert_eq!(
        matched["source_connection_id"],
        "00000000-0000-0000-0000-000000000001"
    );
    // Old public reports retain their index without inventing a wire reference.
    matched
        .as_object_mut()
        .unwrap()
        .remove("source_query_sequence");
    matched
        .as_object_mut()
        .unwrap()
        .remove("source_connection_id");
    let legacy: E2eDirtyCounts = serde_json::from_value(public).unwrap();
    let matched = &legacy.clusters[0]
        .representative
        .as_ref()
        .unwrap()
        .target_matches[0];
    assert_eq!(matched.recorded_index, Some(7));
    assert!(matched.source_query_sequence.is_none());
    assert!(matched.source_connection_id.is_none());
    assert!(!state.replay_report.exists());
}

#[test]
fn unmatched_mysql_select_body_survives_sidecar_and_public_dirty_projection() {
    let temp = tempfile::tempdir().unwrap();
    let state = shared_session(temp.path(), "get-case");
    let columns = (0..24)
        .map(|index| format!("installations.field_{index} AS installations_field_{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let body = "FROM installations WHERE installed_kind_id = ? AND device_id = ? LIMIT 1";
    let sql = format!("SELECT {columns} {body}");
    for command in ["COM_QUERY", "COM_STMT_EXECUTE"] {
        let report = json!({"unmatched_queries":[{
            "case_id":"get-case", "command":command, "sql":sql,
            "reason":"no recorded semantic dependency matched",
            "params":[{"kind":"integer", "value":7}]
        }]});
        let original = report.clone();
        let evidence = build_dependency_evidence(&report);
        std::fs::write(
            dependency_evidence_path(&state.replay_report),
            serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();
        let public = serde_json::to_value(build(&state, true, true).unwrap()).unwrap();
        let signature =
            &public["clusters"][0]["representative"]["difference"]["actual"]["signature"];
        assert_eq!(signature["command"], command);
        assert_eq!(signature["sql_summary"]["select_body"]["preview"], body);
        assert_eq!(signature["sql_summary"]["select_body"]["truncated"], false);
        assert_eq!(signature["sql_summary"]["truncated"], true);
        assert!(signature["sql_summary"]["fingerprint"].as_str().is_some());
        assert!(!signature["sql"].as_str().unwrap().contains("WHERE"));
        assert!(signature.get("params").is_none());
        assert_eq!(public["case_event_counts"]["mysql"]["unmatched_target"], 1);
        assert_eq!(report, original);
        // The public query uses its bounded sidecar, never the private report.
        assert!(!state.replay_report.exists());
    }
}

#[test]
fn dirty_representative_outside_recording_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let state = shared_session(temp.path(), "foreign-case");
    let selected = super::super::focused_batch::project(&state, "OPTIONS /api/notifications");

    let error = build(&selected, true, true).unwrap_err();

    assert!(error.to_string().contains("unknown case \"foreign-case\""));
}

#[test]
fn ambiguous_shared_session_case_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let state = shared_session(temp.path(), "get-case");
    let duplicate = state.case_source.join("apis/another-group/get-case");
    std::fs::create_dir_all(&duplicate).unwrap();
    std::fs::copy(
        state.cases[0].case_dir.join("request.json"),
        duplicate.join("request.json"),
    )
    .unwrap();
    std::fs::write(duplicate.join("expected-response.json"), "{}").unwrap();
    let selected = super::super::focused_batch::project(&state, "OPTIONS /api/notifications");

    let error = build(&selected, true, true).unwrap_err();

    assert!(format!("{error:#}").contains("duplicate case id"));
}

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
            target_matches: Vec::new(),
            target_matches_may_be_truncated: false,
        }),
    };
    let case_dirs = BTreeMap::from([("case-a".to_string(), PathBuf::from("/recording/case-a"))]);
    let startup = BTreeMap::from([("cache.internal:11211".to_string(), 9)]);

    let cluster = enrich_cluster(cluster, &case_dirs, &startup).unwrap();

    assert_eq!(cluster.cluster_id, "dirty-ebf71141ecbd6508");
    assert_eq!(cluster.scope, "case");
    assert_eq!(cluster.source_pre_readiness_interactions, 9);
    let representative = cluster.representative.unwrap();
    assert_eq!(representative.case_id, "case-a");
    assert_eq!(representative.case_dir, PathBuf::from("/recording/case-a"));
    assert_eq!(representative.difference.kind, "unused_recorded");
}

#[test]
fn unscoped_network_cluster_is_run_scoped_without_a_representative() {
    let cluster = ReplayDependencyCluster {
        protocol: "network".to_string(),
        endpoint: Some(ReplayDependencyEndpoint {
            host: "breeze.recording".to_string(),
            port: 9301,
        }),
        reason: "unrecorded_endpoint".to_string(),
        count: 1,
        case_count: 0,
        case_ids: Vec::new(),
        omitted_case_ids: 0,
        operations: BTreeMap::from([("unknown".to_string(), 1)]),
        omitted_operations: 0,
        representative: None,
    };

    let cluster = enrich_cluster(cluster, &BTreeMap::new(), &BTreeMap::new()).unwrap();

    assert_eq!(cluster.scope, "run");
    assert!(cluster.representative.is_none());
}
