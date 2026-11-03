//! Historical sealed evidence uses reusable rules and retains manual proof fallback.
use super::super::{
    AttributionCommandOptions, AttributionRuleBinding, AttributionSubmission, ProposedAttribution,
    analysis, apply_dependency_attribution, dependency_attribution_context, snapshot,
};
use super::*;
use crate::{
    dependency::{attribution::AttributionProof, observation::MANIFEST_FILE},
    recorder::{
        CaseContext, MysqlExchangeEvent, MysqlExchangeResponse, Recorder, RecorderEvent,
        RedisExchangeEvent, capture_body,
    },
    rewrite::{
        RewriteContext,
        model::RewriteState,
        store::RewriteStore,
        verification_obligations::{
            VerificationImpact, VerificationRequirement, VerificationScope,
        },
    },
};
use chrono::Utc;
use serde_json::json;
use std::collections::BTreeSet;

const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
#[ignore = "requires caller-supplied sealed Source and reviewed ownership policy"]
fn external_source_policy_assessment() {
    let source = std::env::var_os("ASYNC_OWNERSHIP_CASE_SOURCE").expect("sealed Source path");
    let proposal = std::env::var_os("ASYNC_OWNERSHIP_POLICY").expect("reviewed policy path");
    let value: serde_yaml::Value = serde_yaml::from_slice(&fs::read(proposal).unwrap()).unwrap();
    let document = value.get("policy").unwrap_or(&value);
    let policy =
        crate::policy::parse_and_compile_policy(&serde_yaml::to_string(document).unwrap()).unwrap();
    let started = std::time::Instant::now();
    let result = materialize(Path::new(&source), &policy.async_api).unwrap();
    let mut compared = 0;
    let mut missing = Vec::new();
    let mut wrong = Vec::new();
    if let Some(proof) = std::env::var_os("ASYNC_OWNERSHIP_EXPECTED_PROOF") {
        let proof: Value = serde_json::from_slice(&fs::read(proof).unwrap()).unwrap();
        for decision in proof["decisions"].as_array().unwrap() {
            let owner: DependencyOwner = serde_json::from_value(decision["owner"].clone()).unwrap();
            for id in decision["source_exchange_ids"].as_array().unwrap() {
                let id: Uuid = serde_json::from_value(id.clone()).unwrap();
                compared += 1;
                match result.owners.get(&id) {
                    Some(actual) if *actual == owner => {}
                    Some(DependencyOwner::Unattributed { .. }) => missing.push(id),
                    Some(_) => wrong.push(id),
                    None => missing.push(id),
                }
            }
        }
    }
    println!(
        "{}",
        json!({"elapsed_seconds":started.elapsed().as_secs_f64(),
        "diagnostic":result.diagnostic,"compared":compared,"missing_count":missing.len(),
        "missing_sample":missing.iter().take(8).collect::<Vec<_>>(),"wrong_count":wrong.len(),
        "wrong_sample":wrong.iter().take(8).collect::<Vec<_>>()})
    );
    assert!(
        wrong.is_empty(),
        "automatic Source ownership contradicts independent proof"
    );
    assert!(
        missing.is_empty(),
        "reviewed policy did not cover all independently proved occurrences"
    );
}

struct Fixture {
    target: tempfile::TempDir,
    state: RewriteState,
    first: Uuid,
    next: Uuid,
    late: Uuid,
    late_ids: BTreeSet<Uuid>,
    central: Vec<u8>,
    manifest: Vec<u8>,
}

fn policy() -> String {
    let declaration = json!({"format":"traffic-policy/v3","source_revision":REVISION,
    "async_api":{"POST /jobs":{
        "when":{},"when_response":{"/status":"in_progress"},
        "end":[{"redis":{"operation":"DEL","key":"cancel:*"}}],
        "ownership":{
            "proof":{"source":"jobs.py:finish","fact":"The detached job reads its own result after cleanup"},
            "origin":{
                "resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},
                "tables":["jobs"],"row_match":{"role":"ASSISTANT"},"bindings":{"task":"task_id","subtask":"id"}
            },
            "requests":[{
                "protocol":"redis","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0,"username":"default"},
                "operation":"GET","arguments":[{"identity":"subtask","prefix":"result:"}]
            }]
        }
    }}});
    let document = crate::policy::parse_policy(&declaration.to_string()).unwrap();
    crate::policy::render_policy(&document).unwrap()
}

fn case(name: &str) -> CaseContext {
    CaseContext {
        id: Uuid::new_v4(),
        rule_name: name.into(),
        uri_group: None,
    }
}

async fn request(recorder: &Recorder, case: &CaseContext, method: &str, uri: &str, body: &[u8]) {
    for (name, value) in [
        ("admission.json", json!({"fixture":true})),
        (
            "request.json",
            json!({"method":method,"uri":uri,"timestamp":Utc::now(),"body":capture_body(body,1024)}),
        ),
    ] {
        recorder.write_case_json(case, name, &value).await.unwrap();
    }
}

async fn response(recorder: &Recorder, case: &CaseContext, body: &[u8]) {
    recorder
        .write_case_json(
            case,
            "expected-response.json",
            &json!({
                "status":200,"timestamp":Utc::now(),"body":capture_body(body,1024)
            }),
        )
        .await
        .unwrap();
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

fn redis(operation: &str, key: &str) -> RecorderEvent {
    RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
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
        command: operation.into(),
        args: vec![capture_body(key.as_bytes(), 1024)],
        response_kind: if operation == "DEL" {
            "integer"
        } else {
            "bulk_string"
        }
        .into(),
        response: capture_body(
            if operation == "DEL" {
                b":0\r\n"
            } else {
                b"$1\r\nx\r\n"
            },
            1024,
        ),
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

async fn fixture(next_references_origin: bool) -> Fixture {
    fixture_with_count(next_references_origin, 1).await
}

async fn fixture_with_count(next_references_origin: bool, late_count: usize) -> Fixture {
    let target = crate::rewrite::worker::tests::configured_target();
    // Historical evidence was sealed without the new ownership declaration.
    let recorder = Recorder::new(target.path().join(".traffic-e2e/local/recordings"))
        .await
        .unwrap();
    let first = case("jobs");
    request(&recorder, &first, "POST", "/jobs", b"{}").await;
    let connection = Uuid::new_v4();
    for event in [
        mysql(
            connection,
            1,
            "INSERT INTO jobs (id,task_id,role) VALUES (20,10,'ASSISTANT')",
            0,
            1,
        ),
        mysql(connection, 2, "COMMIT", 1, 0),
    ] {
        recorder
            .append_case_dependency(&first, &event, "input")
            .await
            .unwrap();
    }
    response(&recorder, &first, br#"{"status":"in_progress"}"#).await;
    recorder
        .append_case_dependency(&first, &redis("DEL", "cancel:20"), "input")
        .await
        .unwrap();
    recorder.publish_case(&first).await.unwrap();
    let next = case("poll");
    let body: &[u8] = if next_references_origin {
        br#"{"subtask_id":20}"#
    } else {
        b"{}"
    };
    request(&recorder, &next, "GET", "/poll", body).await;
    let mut physical_ids = BTreeSet::new();
    for _ in 0..late_count {
        let late = redis("GET", "result:20");
        match &late {
            RecorderEvent::RedisExchange(event) => {
                physical_ids.insert(event.id);
            }
            _ => unreachable!(),
        }
        recorder
            .append_case_dependency(&next, &late, "input")
            .await
            .unwrap();
    }
    response(&recorder, &next, b"{}").await;
    recorder.publish_case(&next).await.unwrap();
    recorder.finish_run().await.unwrap();
    let root = recorder.run_dir.as_ref();
    let central = fs::read(root.join("dependencies.jsonl")).unwrap();
    let manifest = fs::read(root.join(MANIFEST_FILE)).unwrap();
    let sealed: RecordingManifest = serde_json::from_slice(&manifest).unwrap();
    assert_eq!(sealed.semantic_inventory.unattributed_dependencies, 0);
    let rows = central
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .filter(|row| {
            serde_json::from_value::<Uuid>(row["id"].clone())
                .is_ok_and(|id| physical_ids.contains(&id))
        })
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), late_count);
    let late_ids = rows
        .iter()
        .map(|row| {
            assert_eq!(
                row["capture"]["attribution"]["origin_case_id"],
                next.id.to_string()
            );
            serde_json::from_value(row["capture"]["exchange_id"].clone()).unwrap()
        })
        .collect::<BTreeSet<Uuid>>();
    let late = *late_ids.first().unwrap();
    fs::write(target.path().join(".traffic-e2e/policy.yaml"), policy()).unwrap();
    let mut state = crate::rewrite::test_support::test_state();
    state.api = "POST /jobs".into();
    state.source_route = "/jobs".into();
    state.case_source = Some(root.clone());
    state.recording_run_id = root.file_name().unwrap().to_str().unwrap().into();
    state.source_revision = Some(REVISION.into());
    state.recording_apis = vec!["POST /jobs".into(), "GET /poll".into()];
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    Fixture {
        target,
        state,
        first: first.id,
        next: next.id,
        late,
        late_ids,
        central,
        manifest,
    }
}

fn context(fixture: &Fixture) -> super::super::AttributionReviewContext {
    dependency_attribution_context(RewriteContext {
        target_root: fixture.target.path().into(),
    })
    .unwrap()
}

fn assert_originals(fixture: &Fixture) {
    let root = fixture.state.case_source.as_ref().unwrap();
    assert_eq!(
        fs::read(root.join("dependencies.jsonl")).unwrap(),
        fixture.central
    );
    assert_eq!(
        fs::read(root.join(MANIFEST_FILE)).unwrap(),
        fixture.manifest
    );
}

fn apply_manual(fixture: &Fixture, ids: BTreeSet<Uuid>) -> Value {
    let current = context(fixture);
    let file = fixture
        .target
        .path()
        .join(".traffic-e2e/local/manual-attribution.json");
    let input=AttributionSubmission {
        schema:super::super::model::SCHEMA.into(),assignment_id:current.assignment_id,
        expected_revision:current.revision,recording_run_id:current.recording_run_id,
        source_revision:current.source_revision,source_inventory_id:current.source_inventory_id,
        decisions:vec![ProposedAttribution {
            claim_ids:BTreeSet::new(),source_exchange_ids:ids,source_task:"jobs.finish".into(),
            owner:DependencyOwner::Case {origin_case_id:fixture.first,task_instance:None},
            proof:AttributionProof {
                source_revision:REVISION.into(),source_locations:vec!["jobs.py:finish".into(),"poll.py:metadata".into()],
                call_chain:"POST /jobs creates the item; its detached cleanup reads the result key".into(),
                exclusive_scope:"The poll input references this item but its metadata-only Source branch does not issue this GET".into(),
            },
            impact:VerificationImpact::Runtime,
            obligation_scope:VerificationScope::Api {api:"/jobs".into(),method:Some("POST".into()),scenario:Some(0)},
            missing_evidence:None,
            rule_binding:AttributionRuleBinding {policy_fingerprint:current.effective_policy_fingerprint,
                rule_ids:BTreeSet::from(["capture.async_api:POST /jobs".into()])},
        }],
        investigation_resolutions:vec![],unresolved_claim_ids:BTreeSet::new(),claim_rejections:vec![],
    };
    fs::write(&file, serde_json::to_vec(&input).unwrap()).unwrap();
    apply_dependency_attribution(AttributionCommandOptions {
        target_root: fixture.target.path().into(),
        file,
    })
    .unwrap()
}

#[tokio::test]
async fn historical_policy_assigns_a_late_next_case_request_without_rewriting_sealed_evidence() {
    let fixture = fixture(false).await;
    let root = fixture.state.case_source.as_ref().unwrap();
    let defaults = super::super::scope_defaults::load(root, Some(fixture.target.path())).unwrap();
    assert_eq!(
        defaults.owners.get(&fixture.late),
        Some(&DependencyOwner::Case {
            origin_case_id: fixture.first,
            task_instance: None
        })
    );
    let (frozen, identity) = snapshot::frozen(
        Some(fixture.target.path()),
        root,
        &fixture.state.recording_run_id,
    )
    .unwrap();
    assert_eq!(
        frozen.get(&fixture.late),
        defaults.owners.get(&fixture.late)
    );
    assert_ne!(fixture.first, fixture.next);
    assert!(context(&fixture).unattributed_exchange_ids.is_empty());
    let mut refreshed = fixture.state.clone();
    analysis::refresh_inventory(fixture.target.path(), &mut refreshed).unwrap();
    assert!(analysis::required_action(fixture.target.path(), &refreshed).is_none());
    assert!(refreshed.dependency_review.decisions.is_empty());
    assert!(refreshed.attempts.is_empty());
    let cache_root = crate::dependency_index::store::cache_directory(root);
    let cache = fs::read_dir(cache_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("source-ownership-")
        })
        .unwrap();
    let cached = fs::read(&cache).unwrap();
    let stamp = crate::dependency_index::FileStamp::read_native(&cache).unwrap();
    let (again, again_identity) = snapshot::frozen(
        Some(fixture.target.path()),
        root,
        &fixture.state.recording_run_id,
    )
    .unwrap();
    assert_eq!(again, frozen);
    assert_eq!(again_identity, identity);
    assert_eq!(fs::read(&cache).unwrap(), cached);
    assert_eq!(
        crate::dependency_index::FileStamp::read_native(&cache).unwrap(),
        stamp
    );
    assert_originals(&fixture);
}

#[tokio::test]
async fn ambiguous_historical_ownership_accepts_independent_manual_proof_and_retains_real_replay_debt()
 {
    let fixture = fixture(true).await;
    let current = context(&fixture);
    assert_eq!(
        current.unattributed_exchange_ids,
        BTreeSet::from([fixture.late])
    );
    let mut refreshed = fixture.state.clone();
    analysis::refresh_inventory(fixture.target.path(), &mut refreshed).unwrap();
    assert!(analysis::required_action(fixture.target.path(), &refreshed).is_some());
    let applied = apply_manual(&fixture, BTreeSet::from([fixture.late]));
    assert_eq!(applied["unattributed_remaining"], 0);
    assert_eq!(applied["accepted_apis"], json!([]));
    assert_eq!(applied["batch_verified"], false);
    assert!(context(&fixture).unattributed_exchange_ids.is_empty());
    let state = RewriteStore::new(fixture.target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert!(state.attempts.is_empty());
    assert!(state.dependency_review.receipts.is_empty());
    assert!(
        state
            .dependency_review
            .obligations
            .values()
            .any(
                |obligation| obligation.requirement == VerificationRequirement::Replay
                    && obligation.pending()
            )
    );
    let (frozen, _) = snapshot::frozen(
        Some(fixture.target.path()),
        state.case_source.as_ref().unwrap(),
        &state.recording_run_id,
    )
    .unwrap();
    assert_eq!(
        frozen.get(&fixture.late),
        Some(&DependencyOwner::Case {
            origin_case_id: fixture.first,
            task_instance: None
        })
    );
    assert_originals(&fixture);
}

#[tokio::test]
async fn warmed_historical_ownership_cache_cannot_hide_modified_sealed_input() {
    let fixture = fixture(false).await;
    let root = fixture.state.case_source.as_ref().unwrap();
    assert!(super::load(root, Some(fixture.target.path())).is_ok());
    let (_, manifest) = crate::dependency_index::recording::manifest(root).unwrap();
    let input = manifest
        .inputs
        .iter()
        .find(|input| input.case_id == fixture.next)
        .unwrap();
    let request = root.join(&input.path).join("request.json");
    let mut bytes = fs::read(&request).unwrap();
    bytes.push(b' ');
    fs::write(request, bytes).unwrap();
    assert!(super::load(root, Some(fixture.target.path())).is_err());
}

#[tokio::test]
async fn partial_manual_fallback_keeps_other_ambiguous_owned_occurrences_pending() {
    let fixture = fixture_with_count(true, 2).await;
    assert_eq!(
        context(&fixture).unattributed_exchange_ids,
        fixture.late_ids
    );
    let applied = apply_manual(&fixture, BTreeSet::from([fixture.late]));
    assert_eq!(applied["unattributed_remaining"], 1);
    assert_eq!(applied["ownership_complete"], false);
    let expected = fixture
        .late_ids
        .difference(&BTreeSet::from([fixture.late]))
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(context(&fixture).unattributed_exchange_ids, expected);
    let mut stored = RewriteStore::new(fixture.target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    stored.dependency_review.case_defaults_identity = None;
    analysis::refresh_inventory(fixture.target.path(), &mut stored).unwrap();
    assert_eq!(
        stored.dependency_review.unresolved_source_exchange_ids,
        expected
    );
    assert!(analysis::required_action(fixture.target.path(), &stored).is_some());
    assert_originals(&fixture);
}
