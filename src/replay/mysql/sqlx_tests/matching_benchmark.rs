//! Manual matching-stage measurements from captured calls, without network I/O
//! or recorded response delays. Inputs stay outside the repository; supply a
//! MySQL-only policy so unrelated protocol startup is outside the measurement.
use super::*;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs, path::PathBuf, time::Instant};

#[tokio::test]
#[ignore = "manual release-mode benchmark; requires TRAFFIC_E2E_MYSQL_MATCHING_BENCH_INPUT"]
async fn recorded_mysql_matching_benchmark() {
    let path = std::env::var_os("TRAFFIC_E2E_MYSQL_MATCHING_BENCH_INPUT")
        .expect("set the benchmark input JSON path");
    let input: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let root = PathBuf::from(input["case_root"].as_str().unwrap());
    let policy = PathBuf::from(input["policy"].as_str().unwrap());
    let queries = input["queries"].as_array().unwrap();
    for case_id in input["case_ids"].as_array().unwrap() {
        let case_id = case_id.as_str().unwrap();
        // Keep source inputs immutable and all runtime artifacts test-private.
        let temp = tempdir().unwrap();
        let case = temp.path().join(case_id);
        fs::create_dir(&case).unwrap();
        for name in ["dependencies.jsonl", "request.json"] {
            fs::copy(root.join(case_id).join(name), case.join(name)).unwrap();
        }
        // Policy loading requires an assertion-only artifact. The matching
        // benchmark neither reads a response oracle nor asserts an HTTP result.
        fs::write(case.join("expected-response.json"), "{}").unwrap();
        super::super::super::write_test_recording_network_manifest(temp.path());
        let config = ReplayConfig {
            case_dir: case,
            selected_case_ids: vec![],
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".into(),
            report_path: Some(temp.path().join("report.json")),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: None,
            ca_key_path: None,
            policy_path: Some(policy.clone()),
            http_ignore_query_params: vec![],
            process_owned_dependencies: vec![],
            allowed_unused_http: None,
        };
        let calls = queries
            .iter()
            .filter(|q| q["case_id"] == case_id)
            .collect::<Vec<_>>();
        assert!(!calls.is_empty());
        let mut durations = Vec::new();
        let mut expected_fingerprint = None;
        for _ in 0..5 {
            let runtime = ReplayRuntime::load(config.clone(), config.dns_listen, config.tcp_listen)
                .await
                .unwrap();
            let mut state = runtime.state.lock().await;
            state
                .replay_policy
                .as_ref()
                .unwrap()
                .request_contracts
                .request_begin(case_id)
                .unwrap();
            // Prepare once per distinct statement, then execute each captured
            // call with fresh parameters and finite exchange consumption.
            let mut prepared = HashSet::new();
            let mut fingerprint = Sha256::new();
            let started = Instant::now();
            for query in &calls {
                let identity = ReplaySessionIdentity {
                    target: Some(serde_json::from_value(query["target"].clone()).unwrap()),
                    database: query["database"].as_str().map(str::to_owned),
                    username: query["username"].as_str().map(str::to_owned),
                };
                let sql = query["sql"].as_str().unwrap();
                let command = query["command"].as_str().unwrap();
                let params: Option<Vec<RecordedMysqlValue>> =
                    serde_json::from_value(query["params"].clone()).unwrap();
                if command == "COM_STMT_EXECUTE" && prepared.insert(sql) {
                    let _ = state.statement_metadata(&identity, sql);
                }
                let matched = state
                    .match_exchange(&identity, command, Some(sql), params.as_deref())
                    .expect("every captured call must match its case evidence");
                fingerprint.update(matched.index.to_le_bytes());
                state.complete_exchange(&matched);
            }
            durations.push(started.elapsed().as_secs_f64() * 1000.0);
            assert_eq!(state.mysql.events.matched_query_count, calls.len());
            let fingerprint = format!("{:x}", fingerprint.finalize());
            if let Some(expected) = &expected_fingerprint {
                assert_eq!(&fingerprint, expected);
            } else {
                expected_fingerprint = Some(fingerprint);
            }
        }
        durations.sort_by(f64::total_cmp);
        eprintln!(
            "recorded_mysql_matching_benchmark: case={case_id} calls={} median_ms={:.3} min_ms={:.3} max_ms={:.3} matched_indices_sha256={}",
            calls.len(),
            durations[2],
            durations[0],
            durations[4],
            expected_fingerprint.unwrap(),
        );
    }
}
