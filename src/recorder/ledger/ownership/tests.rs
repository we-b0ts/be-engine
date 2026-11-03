use super::*;
use crate::active_case::ActiveCaseRegistry;
use crate::recorder::{
    CaseContext, MysqlExchangeEvent, MysqlExchangeResponse, Recorder, RecorderEvent,
    RedisExchangeEvent, capture_body,
};
use serde_json::json;

fn rules() -> BTreeMap<String, crate::policy::AsyncApiRules> {
    serde_json::from_value(json!({"POST /jobs": [{
        "when": {}, "when_response": {"/status": "running"},
        "end": [{"redis": {"operation": "DEL", "key": "cancel:*"}}],
        "ownership": {
            "proof": {"source": "jobs.py:finish", "fact": "The detached job reads only its own cache key after terminal cleanup."},
            "origin": {
                "resource": {"protocol":"mysql", "endpoint":"db.test:3306", "database":"app", "username":"writer"},
                "table_patterns": ["jobs_*"], "row_match": {"role":"ASSISTANT"},
                "bindings": {"task":"task_id", "subtask":"id"}
            },
            "requests": [{"protocol":"redis",
                "resource": {"protocol":"redis", "endpoint":"cache.test:6379", "database":0, "username":"default"},
                "operation":"GET", "arguments":[{"identity":"subtask", "prefix":"result:"}]
            }]
        }
    }]})).unwrap()
}

async fn recorder() -> (tempfile::TempDir, Recorder) {
    configured_recorder(rules()).await
}

async fn configured_recorder(
    async_api: BTreeMap<String, crate::policy::AsyncApiRules>,
) -> (tempfile::TempDir, Recorder) {
    let temp = tempfile::tempdir().unwrap();
    let config = crate::AppConfig {
        async_api,
        ..Default::default()
    };
    let recorder = Recorder::new(temp.path())
        .await
        .unwrap()
        .with_global_preparation(&config)
        .await
        .unwrap();
    (temp, recorder)
}

fn case() -> CaseContext {
    CaseContext {
        id: Uuid::new_v4(),
        rule_name: "jobs".into(),
        uri_group: None,
    }
}

async fn input(recorder: &Recorder, case: &CaseContext) {
    let at = Utc::now() - chrono::Duration::seconds(1);
    for (name, value) in [
        (
            "request.json",
            json!({"timestamp":at,"method":"POST","uri":"/jobs", "body":capture_body(b"{}",1024)}),
        ),
        (
            "expected-response.json",
            json!({"timestamp":at,"status":200,"body":capture_body(br#"{"status":"running"}"#,1024)}),
        ),
    ] {
        recorder.write_case_json(case, name, &value).await.unwrap();
    }
}

fn mysql(connection: Uuid, sequence: u64, sql: &str, before: u16, after: u16) -> RecorderEvent {
    RecorderEvent::MysqlExchange(MysqlExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: connection,
        query_sequence: sequence,
        timestamp: Utc::now(),
        request_started_at: Utc::now(),
        client_addr: None,
        route_name: None,
        target_host: Some("db.test".into()),
        target_port: Some(3306),
        target_addr: Some("db.test:3306".into()),
        upstream_addr: None,
        username: Some("writer".into()),
        database: Some("app".into()),
        command: "COM_QUERY".into(),
        sql: Some(sql.into()),
        statement_id: None,
        params: None,
        server_status_before: Some(before),
        response: MysqlExchangeResponse {
            wire_prefix: vec![],
            server_status: Some(after),
            status: "ok".into(),
            error_code: None,
            error_message: None,
            affected_rows: Some(1),
            last_insert_id: None,
            columns: vec![],
            rows: vec![],
            row_count: 0,
            rows_truncated: false,
        },
        outcome: crate::DependencyExchangeOutcome::Response,
        duration_ms: 1,
        parse_warnings: vec![],
    })
}

async fn origin(recorder: &Recorder, case: &CaseContext) {
    let connection = Uuid::new_v4();
    for event in [
        mysql(
            connection,
            1,
            "INSERT INTO jobs_1 (id, task_id, role) VALUES (20, 10, 'ASSISTANT')",
            0,
            1,
        ),
        mysql(connection, 2, "COMMIT", 1, 0),
    ] {
        recorder
            .append_case_dependency(case, &event, "input")
            .await
            .unwrap();
    }
    let RecorderEvent::RedisExchange(mut cleanup) = redis("cancel:20", 1, true) else {
        unreachable!();
    };
    cleanup.connection_id = Uuid::new_v4();
    cleanup.command = "DEL".into();
    cleanup.response_kind = "integer".into();
    cleanup.response = capture_body(b":0\r\n", 1024);
    record(
        recorder,
        RecorderEvent::RedisExchange(cleanup),
        case.id,
        Some(case),
    );
}

fn redis(key: &str, sequence: u64, complete: bool) -> RecorderEvent {
    let mut response = capture_body(b"$1\r\nx\r\n", 1024);
    response.truncated = !complete;
    RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::from_u128(99),
        sequence,
        timestamp: Utc::now(),
        request_started_at: Utc::now(),
        client_addr: None,
        target_host: "cache.test".into(),
        target_port: 6379,
        target_addr: "cache.test:6379".into(),
        upstream_addr: "127.0.0.1:6379".into(),
        resp_version: 2,
        database: 0,
        username: Some("default".into()),
        command: "GET".into(),
        args: vec![capture_body(key.as_bytes(), 1024)],
        response_kind: "bulk_string".into(),
        response,
        rpc_callback_capture: None,
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: false,
        outcome: crate::DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: vec![],
    })
}

fn record(recorder: &Recorder, event: RecorderEvent, observed: Uuid, owner: Option<&CaseContext>) {
    let registry = ActiveCaseRegistry::new(true);
    let mut targets = registry.current_targets_for_event();
    targets.bootstrap_open = false;
    targets.phase = CapturePhase::Runtime;
    targets.observed_case = Some(observed);
    if let Some(case) = owner {
        targets.cases.push((case.clone(), "next_input"));
    }
    recorder
        .try_record_event(event, targets, None, false)
        .unwrap();
}

fn read(root: &Path, name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap()
}

fn payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .split_inclusive(|byte| *byte == b'\n')
        .map(|line| {
            let captured: CapturedRecord<'_> = serde_json::from_slice(line).unwrap();
            let start = captured.capture.get().as_ptr() as usize - line.as_ptr() as usize;
            [
                &line[..start],
                &line[start + captured.capture.get().len()..],
            ]
            .concat()
        })
        .collect()
}

#[tokio::test]
async fn live_seal_corrects_finite_late_requests_across_next_case_without_changing_payloads() {
    let (_temp, recorder) = recorder().await;
    let first = case();
    let next = case();
    input(&recorder, &first).await;
    input(&recorder, &next).await;
    origin(&recorder, &first).await;
    recorder.publish_case(&first).await.unwrap();
    for index in 0..43 {
        let (observed, owner) = if index < 37 {
            (first.id, None)
        } else {
            (next.id, Some(&next))
        };
        record(
            &recorder,
            redis("result:20", index + 1, true),
            observed,
            owner,
        );
    }
    record(&recorder, redis("unrelated:20", 44, true), first.id, None);
    record(
        &recorder,
        redis("own-next:99", 45, true),
        next.id,
        Some(&next),
    );
    recorder.publish_case(&next).await.unwrap();
    assert_eq!(
        read(&recorder.case_dir(&first), "dependencies-summary.json")["total_events"],
        3
    );
    assert_eq!(
        read(&recorder.case_dir(&next), "dependencies-summary.json")["total_events"],
        7
    );
    recorder.flush_all_dependency_files().await.unwrap();
    let root = recorder.run_dir.as_ref();
    let before = std::fs::read(root.join("dependencies.jsonl")).unwrap();
    let original: Vec<Value> = before
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    recorder.finish_run().await.unwrap();
    let after = std::fs::read(root.join("dependencies.jsonl")).unwrap();
    assert_eq!(payloads(&before), payloads(&after));
    let effective: Vec<Value> = after
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    for (index, (old, new)) in original.iter().zip(&effective).enumerate() {
        for field in [
            "exchange_id",
            "effect_index",
            "observed_case",
            "admitted_case",
            "protocol_ref",
            "process_epoch",
            "started_at",
            "semantic_required",
        ] {
            assert_eq!(old["capture"][field], new["capture"][field], "{field}");
        }
        if (3..46).contains(&index) {
            assert_eq!(
                new["capture"]["attribution"]["origin_case_id"],
                first.id.to_string()
            );
        }
    }
    let manifest: RecordingManifest = serde_json::from_value(read(root, MANIFEST_FILE)).unwrap();
    assert!(manifest.capture_complete);
    assert_eq!(manifest.records, 48);
    assert_eq!(manifest.unattributed_records, 1);
    assert_eq!(manifest.semantic_inventory.total_mandatory, 48);
    assert_eq!(manifest.semantic_inventory.by_owner_kind["case"], 47);
    assert_eq!(manifest.semantic_inventory.unattributed_dependencies, 1);
    assert_eq!(manifest.coverage.admitted, manifest.coverage.terminal);
    assert_eq!(
        read(&recorder.case_dir(&first), "dependencies-summary.json")["total_events"],
        46
    );
    assert_eq!(
        read(&recorder.case_dir(&next), "dependencies-summary.json")["total_events"],
        1
    );
    let receipt = read(root, RECEIPT);
    assert_eq!(receipt["assignments"].as_array().unwrap().len(), 43);
    assert_eq!(
        receipt["original_ledger"]["sha256"],
        format!("{:x}", Sha256::digest(&before))
    );
    assert_eq!(
        receipt["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|change| change["original_capture"]["attribution"]["kind"] == "unattributed")
            .count(),
        37
    );
    assert_eq!(
        receipt["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .filter(
                |change| change["original_capture"]["attribution"]["origin_case_id"]
                    == next.id.to_string()
            )
            .count(),
        6
    );
    assert!(manifest.files.iter().any(|file| file.path == RECEIPT));
    crate::dependency_index::recording::authenticate(root).unwrap();
    let first_scope: ScopeIndex =
        serde_json::from_value(read(&recorder.case_dir(&first), "dependency-scope.json")).unwrap();
    let next_scope: ScopeIndex =
        serde_json::from_value(read(&recorder.case_dir(&next), "dependency-scope.json")).unwrap();
    assert_eq!(first_scope.locations.len(), 46);
    assert_eq!(next_scope.locations.len(), 1);
    for location in first_scope.locations {
        let start = usize::try_from(location.offset).unwrap();
        let length = usize::try_from(location.length).unwrap();
        assert_eq!(
            location.sha256,
            format!("{:x}", Sha256::digest(&after[start..start + length]))
        );
    }
    let sealed_receipt = std::fs::read(root.join(RECEIPT)).unwrap();
    recorder.finish_run().await.unwrap();
    assert_eq!(
        std::fs::read(root.join("dependencies.jsonl")).unwrap(),
        after
    );
    assert_eq!(std::fs::read(root.join(RECEIPT)).unwrap(), sealed_receipt);
}

#[tokio::test]
async fn ambiguous_origins_stay_unowned_in_the_sealed_inventory() {
    let (_temp, recorder) = recorder().await;
    let first = case();
    let second = case();
    for case in [&first, &second] {
        input(&recorder, case).await;
        origin(&recorder, case).await;
        recorder.publish_case(case).await.unwrap();
    }
    record(&recorder, redis("result:20", 1, true), second.id, None);
    record(
        &recorder,
        redis("result:20", 2, true),
        second.id,
        Some(&second),
    );
    recorder.finish_run().await.unwrap();
    let manifest = read(&recorder.run_dir, MANIFEST_FILE);
    assert_eq!(
        manifest["semantic_inventory"]["unattributed_dependencies"],
        2
    );
    let receipt = read(&recorder.run_dir, RECEIPT);
    assert!(receipt["assignments"].as_array().unwrap().is_empty());
    assert!(!receipt["problems"].as_array().unwrap().is_empty());
    let unresolved = receipt["unresolved"].as_array().unwrap();
    assert_eq!(unresolved.len(), 2);
    assert_eq!(
        unresolved
            .iter()
            .filter(
                |change| change["original_capture"]["attribution"]["origin_case_id"]
                    == second.id.to_string()
            )
            .count(),
        1
    );
    let second_scope: ScopeIndex =
        serde_json::from_value(read(&recorder.case_dir(&second), "dependency-scope.json")).unwrap();
    assert_eq!(second_scope.locations.len(), 3);
    crate::dependency_index::recording::authenticate(&recorder.run_dir).unwrap();
}

#[tokio::test]
async fn ownership_cannot_turn_incomplete_capture_into_complete_recording() {
    let (_temp, recorder) = recorder().await;
    let first = case();
    input(&recorder, &first).await;
    origin(&recorder, &first).await;
    recorder.publish_case(&first).await.unwrap();
    record(&recorder, redis("result:20", 1, false), first.id, None);
    recorder.finish_run().await.unwrap();
    let manifest = read(&recorder.run_dir, MANIFEST_FILE);
    assert_eq!(manifest["capture_complete"], false);
    assert_eq!(manifest["coverage"]["capture_failures"], 1);
    assert_eq!(
        manifest["semantic_inventory"]["unattributed_dependencies"],
        1
    );
    assert!(
        read(&recorder.run_dir, RECEIPT)["assignments"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn failed_classifier_seals_complete_source_with_selected_native_owners_unresolved() {
    let mut invalid = rules();
    invalid.get_mut("POST /jobs").unwrap().0[0]
        .ownership
        .as_mut()
        .unwrap()
        .proof
        .as_mut()
        .unwrap()
        .fact
        .clear();
    let (_temp, recorder) = configured_recorder(invalid).await;
    let first = case();
    let next = case();
    input(&recorder, &first).await;
    input(&recorder, &next).await;
    origin(&recorder, &first).await;
    recorder.publish_case(&first).await.unwrap();
    record(&recorder, redis("result:20", 1, true), next.id, Some(&next));
    recorder.publish_case(&next).await.unwrap();
    recorder.finish_run().await.unwrap();
    let manifest = read(&recorder.run_dir, MANIFEST_FILE);
    assert_eq!(manifest["capture_complete"], true);
    assert_eq!(
        manifest["semantic_inventory"]["unattributed_dependencies"],
        1
    );
    let receipt = read(&recorder.run_dir, RECEIPT);
    assert!(receipt["assignments"].as_array().unwrap().is_empty());
    assert_eq!(receipt["unresolved"].as_array().unwrap().len(), 1);
    assert_eq!(
        receipt["unresolved"][0]["original_capture"]["attribution"]["origin_case_id"],
        next.id.to_string()
    );
    assert_eq!(
        receipt["problems"][0]["reason"],
        "async_ownership_execution_failed"
    );
    crate::dependency_index::recording::authenticate(&recorder.run_dir).unwrap();
}

#[tokio::test]
async fn ownership_adapter_refuses_a_previously_sealed_input() {
    let (_temp, recorder) = recorder().await;
    recorder.finish_run().await.unwrap();
    let path = recorder.run_dir.join("dependencies.jsonl");
    let before = std::fs::read(&path).unwrap();
    let mut ledger = LedgerWriter::new(&recorder.run_dir, Uuid::new_v4(), "policy".into());
    ledger.ownership_rules = rules();
    let error = ledger.apply_declared_ownership().await.unwrap_err();
    assert!(error.to_string().contains("sealed recording"));
    assert_eq!(std::fs::read(path).unwrap(), before);
}
