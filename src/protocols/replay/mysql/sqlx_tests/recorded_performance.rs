//! Manual engine-stage comparison using genuine captured Target SQL requests.
//! No target application, external service, response oracle or host interception.
use super::*;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::Instant};

#[tokio::test]
#[ignore = "manual recorded performance comparison; requires TRAFFIC_E2E_RECORDED_PERF_INPUT"]
async fn captured_candidate_and_evidence_performance() {
    let input: Value = serde_json::from_slice(
        &fs::read(std::env::var_os("TRAFFIC_E2E_RECORDED_PERF_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    let output = PathBuf::from(std::env::var_os("TRAFFIC_E2E_RECORDED_PERF_OUTPUT").unwrap());
    let mut measurements = vec![];
    for workload in input["workloads"].as_array().unwrap() {
        for repeat in 0..input["repeats"].as_u64().unwrap_or(3) {
            let temp = tempdir().unwrap();
            let local = temp.path().join(".traffic-e2e/local");
            // Preserve the original recording-run boundary and confirmed Global
            // subscriptions. All mutable Replay state and output stay private.
            let root = PathBuf::from(workload["case_root"].as_str().unwrap());
            let report_path = local.join("runtime/replay.json");
            fs::create_dir_all(report_path.parent().unwrap()).unwrap();
            let config = ReplayConfig {
                case_dir: root,
                selected_case_ids: vec![],
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: "127.0.0.1:0".parse().unwrap(),
                fake_cidr: "198.18.0.0/15".into(),
                report_path: Some(report_path.clone()),
                session_path: None,
                control_socket_path: None,
                ca_cert_path: None,
                ca_key_path: None,
                policy_path: Some(PathBuf::from(input["policy"].as_str().unwrap())),
                http_ignore_query_params: vec![],
                process_owned_dependencies: crate::config::native_policy::parse_source_policy(
                    &fs::read_to_string(input["policy"].as_str().unwrap()).unwrap(),
                )
                .unwrap()
                .process_owned_dependencies,
                allowed_unused_http: None,
            };
            let mut lifecycle = crate::replay::ReplayLifecycleConfig::default();
            lifecycle.dependency_loading.lazy_cases = true;
            let started = Instant::now();
            let runtime = ReplayRuntime::load_with_lifecycle(
                config.clone(),
                config.dns_listen,
                config.tcp_listen,
                lifecycle,
            )
            .await
            .unwrap();
            let startup_ms = started.elapsed().as_secs_f64() * 1000.;
            let mut fingerprint = Sha256::new();
            let mut cases = vec![];
            for case in workload["case_ids"].as_array().unwrap() {
                let case = case.as_str().unwrap();
                let start = Instant::now();
                let request = crate::replay::control::ReplayControlRequest {
                    command: "begin".into(),
                    case_id: Some(case.into()),
                    fail_on_dirty: false,
                    fail_on_incomplete: false,
                    identity_pairs: Vec::new(),
                    derived_input: None,
                    native_event: None,
                    input_timing: None,
                    socketio_timing: None,
                };
                let result =
                    crate::replay::control::begin_case(&request, runtime.state.clone()).await;
                assert_eq!(result["ok"], true, "{result}");
                let prepare_ms = start.elapsed().as_secs_f64() * 1000.;
                let mut state = runtime.state.lock().await;
                state
                    .replay_policy
                    .as_ref()
                    .unwrap()
                    .request_contracts
                    .restore_request_clock_for_test(
                        case,
                        workload["case_clocks"][case]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap(),
                    );
                let start = Instant::now();
                let mut calls = 0;
                let mut matched = 0;
                let mut query_times = vec![];
                for query in workload["queries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|q| q["case_id"] == case)
                {
                    calls += 1;
                    let query_started = Instant::now();
                    let identity = ReplaySessionIdentity {
                        target: Some(serde_json::from_value(query["target"].clone()).unwrap()),
                        database: query["database"].as_str().map(str::to_owned),
                        username: query["username"].as_str().map(str::to_owned),
                    };
                    let command = query["command"].as_str().unwrap();
                    let sql = query["sql"].as_str();
                    let params: Option<Vec<RecordedMysqlValue>> =
                        serde_json::from_value(query["params"].clone()).unwrap();
                    state.protocols.mysql.observed_at_for_test = Some(
                        query["request_started_at"]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap(),
                    );
                    if let Some(exchange) =
                        state.match_exchange(&identity, command, sql, params.as_deref())
                    {
                        matched += 1;
                        fingerprint.update(
                            serde_json::to_vec(&(
                                case,
                                command,
                                exchange.index,
                                &exchange.record.response,
                            ))
                            .unwrap(),
                        );
                        assert!(exchange.claim.publish_wire());
                        assert!(state.complete_exchange(&exchange));
                    } else if command == "COM_STMT_PREPARE" {
                        let metadata = state.statement_metadata(&identity, sql.unwrap());
                        fingerprint.update(
                            serde_json::to_vec(&(
                                case,
                                command,
                                metadata.param_count,
                                metadata.columns,
                            ))
                            .unwrap(),
                        );
                    } else if sql.is_some_and(|sql| {
                        builtin_response(sql, identity.database.as_deref()).is_some()
                    }) {
                        state.record_builtin(
                            &identity,
                            command,
                            sql,
                            "captured driver/session request",
                        );
                        fingerprint
                            .update(serde_json::to_vec(&(case, command, "builtin")).unwrap());
                    } else {
                        state.record_unmatched(
                            &identity,
                            command,
                            sql,
                            params.as_deref(),
                            "captured request has no matching exchange",
                        );
                        fingerprint
                            .update(serde_json::to_vec(&(case, command, "unmatched")).unwrap());
                    }
                    query_times.push(json!({"call":calls,"command":command,
                        "elapsed_ms":query_started.elapsed().as_secs_f64()*1000.}));
                }
                let match_ms = start.elapsed().as_secs_f64() * 1000.;
                state.cases.get_mut(case).unwrap().status = crate::replay::ReplayCaseStatus::Ended;
                state.active_case_id = None;
                cases.push(json!({"case":case,"prepare_ms":prepare_ms,"match_ms":match_ms,"calls":calls,"matched":matched,"query_times":query_times}));
            }
            let state = runtime.state.lock().await;
            let start = Instant::now();
            state
                .replay_policy
                .as_ref()
                .unwrap()
                .request_contracts
                .seal_witnesses()
                .unwrap();
            let report = serde_json::to_value(state.snapshot_report()).unwrap();
            fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
            let manifest: crate::policy_evidence::WitnessManifest =
                serde_json::from_value(report["policy_witnesses"].clone()).unwrap();
            if manifest.complete {
                crate::policy_evidence::verify(&report_path, &manifest).unwrap();
            }
            let seal_ms = start.elapsed().as_secs_f64() * 1000.;
            let artifact_bytes: u64 = fs::read_dir(report_path.parent().unwrap())
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("policy-witnesses-")
                })
                .map(|p| fs::metadata(p).unwrap().len())
                .sum();
            fingerprint.update(serde_json::to_vec(&report["replay_policy"]).unwrap());
            fingerprint.update(serde_json::to_vec(&report["unused_case_exchanges"]).unwrap());
            fingerprint.update(serde_json::to_vec(&report["unmatched_queries"]).unwrap());
            measurements.push(json!({"api":workload["api"],"repeat":repeat,"startup_ms":startup_ms,"cases":cases,"seal_ms":seal_ms,"artifact_bytes":artifact_bytes,"report_bytes":fs::metadata(&report_path).unwrap().len(),"witness_complete":manifest.complete,"witness_observed":manifest.observed,"witness_omitted":manifest.omitted,"semantic_sha256":format!("{:x}",fingerprint.finalize())}));
            fs::write(&output, serde_json::to_vec_pretty(&measurements).unwrap()).unwrap();
            eprintln!(
                "recorded performance: {} repeat={} artifact_bytes={} complete={}",
                workload["api"], repeat, artifact_bytes, manifest.complete
            );
        }
    }
}
