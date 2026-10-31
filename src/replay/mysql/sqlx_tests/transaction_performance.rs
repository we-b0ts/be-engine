//! Self-contained manual engine-stage comparison, portable to the parent revision.
//! Fresh fixtures have no engine indexes; this does not flush OS filesystem caches.
use super::*;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, time::Instant};

const CASES: usize = 128;
const CALLS: usize = 64;
const WARM_LOADS: usize = 5;
const SELECTED: usize = 73;

fn case_id(index: usize) -> String {
    format!("case-{index:03}")
}

fn sql(case: usize, call: usize) -> String {
    format!("SELECT id FROM benchmark_items WHERE bucket={case} AND id={call}")
}

fn record(connection: Uuid, sequence: usize, statement: &str, id: usize) -> Value {
    json!({
        "event_type":"mysql_exchange", "timestamp":"2020-01-01T00:00:00Z", "duration_ms":0,
        "target_host":"mysql.perf.test", "target_port":3306,
        "database":"benchmark", "username":"reader", "command":"COM_QUERY", "sql":statement,
        "connection_id":connection, "query_sequence":sequence, "server_status_before":0,
        "outcome":"response", "parse_warnings":[],
        "response":{
            "status":"resultset", "server_status":0, "rows_truncated":false,
            "columns":[{"name":"id", "family":"integer", "sql_type":"BIGINT"}],
            "rows":[[{"kind":"integer", "value":id}]]
        }
    })
}

fn write_records(path: &Path, records: impl Iterator<Item = Value>) {
    let text = records
        .map(|record| format!("{record}\n"))
        .collect::<String>();
    fs::write(path, text).unwrap();
}

fn fixture(root: &Path) {
    fs::create_dir_all(root).unwrap();
    fs::write(
        root.join("recording-run.json"),
        r#"{"status":"completed","run_id":"mysql-engine-stage-performance"}"#,
    )
    .unwrap();
    for case in 0..CASES {
        let directory = root.join(case_id(case));
        fs::create_dir_all(&directory).unwrap();
        let connection = Uuid::from_u128(case as u128 + 1);
        write_records(
            &directory.join("dependencies.jsonl"),
            (0..CALLS).map(|call| record(connection, call + 1, &sql(case, call), call)),
        );
    }
    let global_connection = Uuid::from_u128(CASES as u128 + 1);
    write_records(
        &root.join("global-dependencies.jsonl"),
        (0..CALLS).map(|call| {
            record(
                global_connection,
                call + 1,
                &format!("SELECT id FROM benchmark_global WHERE id={call}"),
                call,
            )
        }),
    );
    crate::replay::write_test_recording_network_manifest(root);
}

#[derive(Debug)]
struct Measurement {
    startup_ms: f64,
    prepare_ms: f64,
    matching_ms: f64,
    fingerprint: String,
    matched: usize,
}

async fn measure(root: &Path, artifacts: &Path, lazy: bool) -> Measurement {
    let address = "127.0.0.1:0".parse().unwrap();
    let config = ReplayConfig {
        case_dir: root.into(),
        selected_case_ids: vec![],
        dns_listen: address,
        tcp_listen: address,
        fake_cidr: "198.18.0.0/15".into(),
        report_path: Some(artifacts.join("report.json")),
        session_path: None,
        control_socket_path: None,
        ca_cert_path: Some(artifacts.join("ca.pem")),
        ca_key_path: Some(artifacts.join("ca-key.pem")),
        policy_path: None,
        http_ignore_query_params: vec![],
        process_owned_dependencies: vec![],
        allowed_unused_http: None,
    };
    let mut lifecycle = crate::replay::ReplayLifecycleConfig::default();
    lifecycle.dependency_loading.lazy_cases = lazy;
    let started = Instant::now();
    let runtime = ReplayRuntime::load_with_lifecycle(config, address, address, lifecycle)
        .await
        .unwrap();
    let startup_ms = started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(runtime.state.lock().await.cases.len(), CASES);

    let selected = case_id(SELECTED);
    let request = crate::replay::control::ReplayControlRequest {
        command: "begin".into(),
        case_id: Some(selected.clone()),
        fail_on_dirty: true,
        fail_on_incomplete: false,
        identity_pairs: Vec::new(),
        derived_input: None,
        native_event: None,
        input_timing: None,
        socketio_timing: None,
    };
    let started = Instant::now();
    let prepared = crate::replay::control::begin_case(&request, runtime.state.clone()).await;
    let prepare_ms = started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(prepared["ok"], true, "{prepared}");

    let identity = ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "mysql.perf.test".into(),
            port: 3306,
        }),
        database: Some("benchmark".into()),
        username: Some("reader".into()),
    };
    let queries = (0..CALLS)
        .map(|call| sql(SELECTED, call))
        .collect::<Vec<_>>();
    let mut state = runtime.state.lock().await;
    // Keep digest serialization outside the matching timer. Original wire
    // identity and delivered values are stable across eager/lazy inventory order.
    let mut observations = Vec::with_capacity(CALLS);
    let started = Instant::now();
    for sql in &queries {
        let metadata = state.statement_metadata(&identity, sql);
        assert_eq!(metadata.param_count, 0);
        assert_eq!(metadata.columns.len(), 1);
        let matched = state
            .match_exchange(&identity, "COM_QUERY", Some(sql), None)
            .expect("every generated SQL must consume its recorded evidence");
        assert!(matched.claim.publish_wire());
        assert!(state.complete_exchange(&matched));
        observations.push((metadata, matched.record));
    }
    let matching_ms = started.elapsed().as_secs_f64() * 1000.0;
    let matched = state.mysql.events.matched_query_count;
    assert_eq!(matched, CALLS);
    assert!(state.mysql.events.unmatched_queries.is_empty());
    assert!(
        state
            .unused_exchanges(ReplaySource::Case)
            .iter()
            .all(|exchange| exchange.case_id.as_deref() != Some(selected.as_str()))
    );
    assert!(!state.mysql.case_is_dirty(&selected));
    let mut digest = Sha256::new();
    for (metadata, record) in observations {
        digest.update(
            serde_json::to_vec(&(
                record.connection_id,
                record.query_sequence,
                record.command,
                record.sql,
                metadata.param_count,
                metadata.columns,
                record.response.status,
                record.response.server_status,
                record.response.columns,
                record.response.rows,
            ))
            .unwrap(),
        );
    }
    Measurement {
        startup_ms,
        prepare_ms,
        matching_ms,
        fingerprint: format!("{:x}", digest.finalize()),
        matched,
    }
}

fn median(values: impl Iterator<Item = f64>) -> f64 {
    let mut values = values.collect::<Vec<_>>();
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

#[tokio::test]
#[ignore = "manual engine-stage benchmark; run with --ignored --nocapture"]
async fn mysql_transaction_engine_stage_performance() {
    let mut expected_fingerprint = None;
    for lazy in [true, false] {
        // Keeping both recording and cache paths under this private .traffic-e2e
        // root ensures that cold runs and all generated artifacts stay isolated.
        let temp = tempdir().unwrap();
        let local = temp.path().join(".traffic-e2e/local");
        let root = local.join("recordings/performance-run");
        let artifacts = local.join("runtime/performance");
        fs::create_dir_all(&artifacts).unwrap();
        fixture(&root);
        let cold = measure(&root, &artifacts, lazy).await;
        let mut warm = Vec::with_capacity(WARM_LOADS);
        for _ in 0..WARM_LOADS {
            warm.push(measure(&root, &artifacts, lazy).await);
        }
        for measurement in std::iter::once(&cold).chain(&warm) {
            assert_eq!(measurement.matched, CALLS);
            if let Some(expected) = &expected_fingerprint {
                assert_eq!(&measurement.fingerprint, expected);
            } else {
                expected_fingerprint = Some(measurement.fingerprint.clone());
            }
        }
        eprintln!(
            "mysql_transaction_engine_stages {}",
            json!({
                "mode":if lazy {"lazy"} else {"eager"},
                "cases":CASES, "calls_per_case":CALLS, "global_calls":CALLS,
                "selected_case":case_id(SELECTED), "warm_loads":WARM_LOADS,
                "cold":{
                    "startup_ms":cold.startup_ms,
                    "prepare_ms":cold.prepare_ms,
                    "matching_ms":cold.matching_ms
                },
                "warm_median":{
                    "startup_ms":median(warm.iter().map(|value| value.startup_ms)),
                    "prepare_ms":median(warm.iter().map(|value| value.prepare_ms)),
                    "matching_ms":median(warm.iter().map(|value| value.matching_ms))
                },
                "matched":cold.matched, "matched_sha256":cold.fingerprint
            })
        );
    }
}
