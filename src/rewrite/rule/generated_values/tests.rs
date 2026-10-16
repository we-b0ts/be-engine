use super::*;
use crate::rewrite::{RewriteContext, store::RewriteStore};
use std::fs;

pub(in crate::rewrite::rule) struct Fixture {
    pub(in crate::rewrite::rule) target: tempfile::TempDir,
    pub(in crate::rewrite::rule) state: RewriteState,
    options: RewriteRulePlanOptions,
    pub(in crate::rewrite::rule) evidence: crate::E2eResponseRuleEvidence,
    case: std::path::PathBuf,
}

pub(in crate::rewrite::rule) fn jwt_fixture() -> Fixture {
    let mut f = fixture();
    let root = f.target.path();
    fs::write(
        root.join(".traffic-e2e/local/target.env"),
        "SECRET_KEY=fixture-signing-key\n",
    )
    .unwrap();
    let source_time = 1_700_000_000;
    let target_time = source_time + 86_400;
    let request_path = f.case.join("request.json");
    let expected_path = f.case.join("expected-response.json");
    let actual_path = f.case.join("actual-response.json");
    fs::write(&request_path, json!({"method":"GET","uri":"/api","timestamp":chrono::DateTime::from_timestamp(source_time,0).unwrap()}).to_string()).unwrap();
    for (path, time) in [(&expected_path, source_time), (&actual_path, target_time)] {
        let token = crate::request_rules::tests::token(
            json!({"sub":"user","iat":time,"nbf":time-1,"exp":time+1800}),
            "fixture-signing-key",
        );
        fs::write(path, json!({"version":1,"status":200,"headers":{},
            "request_sent_at":chrono::DateTime::from_timestamp(time,0).unwrap(),
            "body":{"encoding":"utf8","truncated":false,"data":json!({"access_token":token}).to_string()}}).to_string()).unwrap();
    }
    let report = crate::assert_recorded_response(crate::ResponseAssertionOptions {
        case_id: "case-1".into(),
        request: request_path,
        expected_response: expected_path,
        actual_response: actual_path,
        policy: root.join(".traffic-e2e/verification.yaml"),
    })
    .unwrap();
    let detail = f.evidence.assertions.with_file_name("case-1-detail.json");
    let detail_bytes = serde_json::to_vec(&report).unwrap();
    fs::write(&detail, &detail_bytes).unwrap();
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in &detail_bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
    }
    fs::write(&f.evidence.assertions, json!({"version":4,"case_source":f.state.case_source,
        "expected_response":"assertions_only","assertion_mode":"runner_owned","policy_fingerprint":report.policy_fingerprint,
        "cases":[{"case_id":"case-1","response":{"method":"GET","path":"/api","detail_report":detail,
            "detail_fingerprint":format!("fnv1a64:{hash:016x}")}}]}).to_string()).unwrap();
    fs::write(&f.evidence.aggregate, json!({"case_source":f.state.case_source,"selected_case_ids":["case-1"],"complete":true,"dirty":false}).to_string()).unwrap();
    let rule = serde_json::from_value(json!({"pointer":"/access_token","algorithm":"HS256",
        "signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},
        "source_evidence":"auth.rs: signs response JWTs with SECRET_KEY for 30 minutes"}))
    .unwrap();
    let mut record = f.state.rule_plan.take().unwrap();
    record.dynamic_value = None;
    record.response_jwts = vec![rule];
    record.kind = "response_jwt".into();
    record.generated_witnesses = build_unfrozen(root, &f.state, &record)
        .unwrap()
        .evidence_witnesses();
    f.options.dynamic_value = None;
    f.options.response_jwts = record.response_jwts.clone();
    f.state.rule_plan = Some(record);
    plan(root, &mut f.state, f.options.clone()).unwrap();
    RewriteStore::new(root).unwrap().save(&f.state).unwrap();
    f
}

fn fixture() -> Fixture {
    let target = crate::rewrite::worker::tests::configured_target();
    let root = target.path();
    fs::write(
        root.join(".traffic-e2e/Dockerfile.target"),
        "FROM scratch\n",
    )
    .unwrap();
    let source = root.join(".traffic-e2e/local/artifacts/recordings/recording");
    let case = source.join("case-1");
    fs::create_dir_all(&case).unwrap();
    fs::write(
        case.join("request.json"),
        r#"{"method":"GET","uri":"/api"}"#,
    )
    .unwrap();
    let source_event = json!({
        "event_type":"mysql_exchange", "target_host":"db.internal", "target_port":3306,
        "database":"app", "username":"user", "command":"COM_QUERY",
        "sql":"SELECT id FROM kinds WHERE name='old-name' AND uid=7", "parse_warnings":[],
        "response":{"status":"resultset","columns":[{"name":"id","family":"integer","sql_type":"BIGINT"}],"rows":[]}
    });
    fs::write(case.join("dependencies.jsonl"), source_event.to_string()).unwrap();
    let evidence = crate::e2e_run::jwt_evidence::test_support::install_attempt(
        root,
        &source,
        &[(case.clone(), 200, 200)],
        chrono::Utc::now(),
    );
    let policy_path = root.join(".traffic-e2e/verification.yaml");
    let report = json!({
        "finalized":true,"replay_policy":{"fingerprint":crate::validate_replay_policy(&policy_path).unwrap().fingerprint},
        "cases":[{"case_id":"case-1","case_dir":case}],
        "unmatched_queries":[{"case_id":"case-1","command":"COM_STMT_EXECUTE",
            "target":{"host":"db.internal","port":3306},"database":"app","username":"user",
            "sql":"SELECT id FROM kinds WHERE name=? AND uid=?",
            "params":[{"kind":"string","value":"new-name"},{"kind":"integer","value":7}]}]
    });
    fs::write(&evidence.replay, report.to_string()).unwrap();
    for path in [&evidence.assertions, &evidence.aggregate] {
        fs::write(path, "{}").unwrap();
    }
    fs::write(
        crate::replay::report::dependency_evidence_path(&evidence.replay),
        "{}",
    )
    .unwrap();
    let rule: crate::DynamicValueRule = serde_json::from_value(json!({
        "id":"name", "api":"/api", "targets":[{"host":"db.internal","port":3306}],
        "capture":{"protocol":"mysql","target":{"host":"db.internal","port":3306},
            "database":"app","sql":"SELECT id FROM kinds WHERE name=? AND uid=?","value_index":0},
        "source_evidence":"NameFactory:create generates a request-local name"
    }))
    .unwrap();
    let mut state = crate::rewrite::worker::tests::implementation_state_with_inventory(false);
    state.case_source = Some(source);
    state.group_id = Some("GET /api".into());
    let mut record: RewriteRulePlanRecord = serde_json::from_value(json!({
        "id":"reviewed-plan", "issue_id":state.active_issue.as_ref().unwrap().id,
        "kind":"dynamic_value", "json_pointer":"", "evidence_id":"reviewed-evidence", "dynamic_value":rule
    })).unwrap();
    // Begin with a valid reviewed engine preview, then exercise the coordinator's
    // pending-plan path and persistence exactly as separate plan/apply calls do.
    let preview = build_unfrozen(root, &state, &record).unwrap();
    record.generated_witnesses = preview.evidence_witnesses();
    state.rule_plan = Some(record);
    let options = RewriteRulePlanOptions {
        response_jwts: Vec::new(),
        header_dates: Vec::new(),
        dynamic_value: Some(rule),
        mysql_time: None,
        redis_time: None,
        dependency_request: None,
        evidence_id: "reviewed-evidence".into(),
        jwt: None,
        body_codec: ResponseBodyCodec::Json,
        kind: None,
        time: None,
        json_pointer: None,
        source_evidence: None,
        source_example: None,
        target_example: None,
        separator: None,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
    };
    plan(root, &mut state, options.clone()).unwrap();
    assert!(state.rule_plan.as_ref().unwrap().generated_witnesses.len() >= 4);
    RewriteStore::new(root).unwrap().save(&state).unwrap();
    Fixture {
        target,
        state,
        options,
        evidence,
        case,
    }
}

fn redis_time() -> crate::DynamicValueRedisTimeRule {
    serde_json::from_value(json!({
        "id":"item-time", "method":"GET",
        "time_values":[{"json_pointer":"/timestamp","format":"unix_milliseconds"}],
        "source_evidence":"ItemFactory:create stores the current millisecond timestamp"
    }))
    .unwrap()
}

#[test]
fn redis_companion_record_is_optional_and_round_trips_without_changing_legacy_records() {
    let legacy = json!({"id":"plan","issue_id":"issue","kind":"dynamic_value",
        "json_pointer":"","evidence_id":"evidence"});
    let mut record: RewriteRulePlanRecord = serde_json::from_value(legacy).unwrap();
    assert!(record.redis_time.is_none());
    assert!(
        serde_json::to_value(&record)
            .unwrap()
            .get("redis_time")
            .is_none()
    );
    record.redis_time = Some(redis_time());
    let restored: RewriteRulePlanRecord =
        serde_json::from_value(serde_json::to_value(record).unwrap()).unwrap();
    assert_eq!(restored.redis_time, Some(redis_time()));
}

#[test]
fn companion_guards_reject_invalid_public_options_without_mutating_policy_or_state() {
    for invalid in ["redis_without_identity", "both_companions"] {
        let mut f = fixture();
        let root = f.target.path();
        let before = serde_json::to_value(&f.state).unwrap();
        let policy = fs::read(root.join(".traffic-e2e/verification.yaml")).unwrap();
        let mut options = f.options.clone();
        options.redis_time = Some(redis_time());
        if invalid == "redis_without_identity" {
            options.dynamic_value = None;
        } else {
            options.mysql_time = Some(
                serde_json::from_value(json!({
                    "id":"sql-time", "time_values":[{"value_index":1}],
                    "source_evidence":"ItemModel:created_at uses the current time"
                }))
                .unwrap(),
            );
        }
        let error = super::super::plan(root, &mut f.state, options).unwrap_err();
        let expected = if invalid == "redis_without_identity" {
            "a Redis time companion requires a dynamic identity rule"
        } else {
            "MySQL and Redis time companions cannot be combined"
        };
        assert!(format!("{error:#}").contains(expected));
        assert_eq!(serde_json::to_value(&f.state).unwrap(), before);
        assert_eq!(
            fs::read(root.join(".traffic-e2e/verification.yaml")).unwrap(),
            policy
        );
        assert_eq!(
            serde_json::to_value(RewriteStore::new(root).unwrap().load().unwrap().unwrap())
                .unwrap(),
            before
        );
    }
}

fn redis_fixture() -> Fixture {
    let mut f = fixture();
    let root = f.target.path();
    let local = root.join(".traffic-e2e/local");
    let encryption_key = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    fs::create_dir_all(encryption_key.parent().unwrap()).unwrap();
    fs::write(
        encryption_key,
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    fs::write(
        f.case.join("request.json"),
        json!({"method":"GET","uri":"/api",
        "timestamp":"1970-01-01T00:16:40Z",
        "body":{"encoding":"utf8","truncated":false,"data":"{\"mode\":\"generated\"}"}})
        .to_string(),
    )
    .unwrap();
    let arguments = |stamp| {
        vec![
            b"items:7".to_vec(),
            json!({"id":format!("item-{stamp}"),
        "timestamp":stamp,"content_key":format!("payload:7:item-{stamp}"),"stable":true})
            .to_string()
            .into_bytes(),
        ]
    };
    let source = arguments(1_000_100);
    let target = arguments(2_000_100);
    let captured = |bytes: &[u8]| {
        json!({"encoding":"utf8","truncated":false,
        "data":String::from_utf8(bytes.to_vec()).unwrap()})
    };
    fs::write(f.case.join("dependencies.jsonl"), json!({"event_type":"redis_exchange",
        "target_host":"cache.test","target_port":6379,"database":0,"command":"RPUSH",
        "outcome":"response","replay_safe":true,"args":source.iter().map(|bytes|captured(bytes)).collect::<Vec<_>>(),
        "response":{"encoding":"utf8","truncated":false,"data":":1\r\n"}}).to_string()).unwrap();
    let fingerprint = |bytes: &[u8]| {
        let hash = bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        });
        format!("fnv1a64:{hash:016x}")
    };
    let source_fingerprint = fingerprint(&serde_json::to_vec(&source).unwrap());
    let target_bytes = serde_json::to_vec(&target).unwrap();
    let target_fingerprint = fingerprint(&target_bytes);
    let actual_anchor = chrono::DateTime::from_timestamp(2000, 0).unwrap();
    let metadata = serde_json::to_string(&(
        "case-1",
        "redis_json_request",
        "cache.test",
        6379,
        "RPUSH",
        0,
        "",
        &source_fingerprint,
        &target_fingerprint,
        actual_anchor,
    ))
    .unwrap();
    let encrypted_target = crate::request_headers::encrypt_evidence(
        &f.case,
        &format!("dependency-request:{metadata}"),
        &target_bytes,
    )
    .unwrap();
    fs::write(&f.evidence.replay, json!({"finalized":true,
        "replay_policy":{"fingerprint":crate::validate_replay_policy(&root.join(".traffic-e2e/verification.yaml")).unwrap().fingerprint,
            "request_contract_candidates":[{"case_id":"case-1","capability":"redis_json_request",
                "host":"cache.test","port":6379,"command":"RPUSH","database":0,"path":"",
                "source_fingerprint":source_fingerprint,"target_fingerprint":target_fingerprint,
                "actual_anchor":actual_anchor,"encrypted_target":encrypted_target}]},
        "cases":[{"case_id":"case-1","case_dir":f.case}]}).to_string()).unwrap();
    let rule = serde_json::from_value(json!({"id":"item-id","api":"/api",
        "targets":[{"host":"cache.test","port":6379}],
        "when":{"request_body_json":{"/mode":{"equals":"generated"}}},
        "capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},
            "database":0,"command":"RPUSH","key":{"prefix":"items:","numeric":true},
            "argument_index":1,"json_pointer":"/id",
            "references":[{"json_pointer":"/content_key","template":"payload:{key_middle}:{value}"}],
            "derived_from":{"json_pointer":"/timestamp","prefix":"item-"}},
        "source_evidence":"ItemFactory:create derives an identity and its payload reference from current milliseconds"
    })).unwrap();
    f.options.dynamic_value = Some(rule);
    f.options.redis_time = Some(redis_time());
    let mut record = f.state.rule_plan.take().unwrap();
    record.kind = "dynamic_value_redis_time".into();
    record.dynamic_value = f.options.dynamic_value.clone();
    record.redis_time = f.options.redis_time.clone();
    record.generated_witnesses = build_unfrozen(root, &f.state, &record)
        .unwrap()
        .evidence_witnesses();
    f.state.rule_plan = Some(record);
    super::super::plan(root, &mut f.state, f.options.clone()).unwrap();
    RewriteStore::new(root).unwrap().save(&f.state).unwrap();
    f
}

#[test]
fn redis_joint_coordinator_applies_one_frozen_plan_and_requests_fresh_replay() {
    let f = redis_fixture();
    let root = f.target.path();
    let store = RewriteStore::new(root).unwrap();
    let restored = store.load().unwrap().unwrap();
    let record = restored.rule_plan.as_ref().unwrap();
    assert_eq!(record.kind, "dynamic_value_redis_time");
    assert_eq!(record.redis_time, Some(redis_time()));
    assert!(
        crate::rewrite::recover_rewrite_rule_plan(
            RewriteContext {
                target_root: root.into()
            },
            &record.id
        )
        .is_err()
    );
    let source = fs::read(f.case.join("dependencies.jsonl")).unwrap();
    let result = crate::rewrite::apply_rewrite_rule(
        RewriteContext {
            target_root: root.into(),
        },
        &record.id,
    )
    .unwrap();
    assert_eq!(
        result.traffic_e2e_report["kind"],
        "dynamic_value_redis_time"
    );
    assert_eq!(
        result.traffic_e2e_report["added_rule_ids"],
        json!(["item-id", "item-time"])
    );
    assert_eq!(result.traffic_e2e_report["applied"], true);
    assert_eq!(result.traffic_e2e_report["requires_fresh_replay"], true);
    let applied = store.load().unwrap().unwrap();
    assert!(applied.rule_plan.is_none() && applied.rule_replay_pending && !applied.e2e_current);
    assert_eq!(
        serde_json::to_value(&applied.attempts).unwrap(),
        serde_json::to_value(&f.state.attempts).unwrap()
    );
    assert_eq!(
        serde_json::to_value(applied.api_inventory).unwrap(),
        serde_json::to_value(f.state.api_inventory).unwrap()
    );
    assert_eq!(fs::read(f.case.join("dependencies.jsonl")).unwrap(), source);
    let policy = fs::read_to_string(root.join(".traffic-e2e/verification.yaml")).unwrap();
    assert!(policy.contains("item-id") && policy.contains("item-time"));
}

#[test]
fn redis_joint_stale_evidence_recovers_with_both_selectors_without_policy_changes() {
    let f = redis_fixture();
    let root = f.target.path();
    let record = f.state.rule_plan.as_ref().unwrap();
    let policy = fs::read(root.join(".traffic-e2e/verification.yaml")).unwrap();
    fs::remove_file(f.case.join("request.json")).unwrap();
    assert!(
        crate::rewrite::apply_rewrite_rule(
            RewriteContext {
                target_root: root.into()
            },
            &record.id
        )
        .is_err()
    );
    let result = crate::rewrite::recover_rewrite_rule_plan(
        RewriteContext {
            target_root: root.into(),
        },
        &record.id,
    )
    .unwrap();
    assert_eq!(result["status"], "fresh_replay_required");
    assert_eq!(result["applied"], false);
    assert_eq!(result["retired_plan"]["dynamic_value"]["id"], "item-id");
    assert_eq!(result["retired_plan"]["redis_time"]["id"], "item-time");
    let recovered = RewriteStore::new(root).unwrap().load().unwrap().unwrap();
    assert!(
        recovered.rule_plan.is_none() && recovered.rule_replay_pending && !recovered.e2e_current
    );
    assert_eq!(
        fs::read(root.join(".traffic-e2e/verification.yaml")).unwrap(),
        policy
    );
}

#[test]
fn generated_plan_survives_revision_bumps_and_applies_only_the_frozen_preview() {
    let mut f = fixture();
    let root = f.target.path();
    let source = fs::read(f.case.join("dependencies.jsonl")).unwrap();
    let plan_id = f.state.rule_plan.as_ref().unwrap().id.clone();
    f.state.bump();
    RewriteStore::new(root).unwrap().save(&f.state).unwrap();
    let result = crate::rewrite::apply_rewrite_rule(
        RewriteContext {
            target_root: root.into(),
        },
        &plan_id,
    )
    .unwrap();
    assert_eq!(result.traffic_e2e_report["applied"], true);
    assert_eq!(result.traffic_e2e_report["requires_fresh_replay"], true);
    let applied = RewriteStore::new(root).unwrap().load().unwrap().unwrap();
    assert!(applied.rule_plan.is_none());
    assert!(applied.rule_replay_pending && !applied.e2e_current);
    assert_eq!(
        serde_json::to_value(applied.attempts.clone()).unwrap(),
        serde_json::to_value(f.state.attempts.clone()).unwrap()
    );
    assert_eq!(
        serde_json::to_value(applied.api_inventory.clone()).unwrap(),
        serde_json::to_value(f.state.api_inventory.clone()).unwrap()
    );
    assert_eq!(fs::read(f.case.join("dependencies.jsonl")).unwrap(), source);
    assert!(
        fs::read_to_string(root.join(".traffic-e2e/verification.yaml"))
            .unwrap()
            .contains("dynamic_value")
    );
}

#[test]
fn same_policy_and_summary_cannot_replace_frozen_report_request_or_dependency_bytes() {
    for witness in ["report", "request", "dependencies"] {
        let mut f = fixture();
        let root = f.target.path();
        let path = match witness {
            "report" => f.evidence.replay.clone(),
            "request" => f.case.join("request.json"),
            _ => f.case.join("dependencies.jsonl"),
        };
        // Whitespace changes the original bytes while preserving all decoded
        // facts, selectors, source proof and the current policy identity.
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
        let pending = f.state.rule_plan.as_ref().unwrap().clone();
        assert!(build_unfrozen(root, &f.state, &pending).is_ok());
        let store = RewriteStore::new(root).unwrap();
        let before = serde_json::to_value(&f.state).unwrap();
        let policy_path = root.join(".traffic-e2e/verification.yaml");
        let policy = fs::read(&policy_path).unwrap();
        let error = plan(root, &mut f.state, f.options.clone()).unwrap_err();
        assert!(format!("{error:#}").contains("evidence changed after planning"));
        assert_eq!(serde_json::to_value(&f.state).unwrap(), before);
        let error = crate::rewrite::apply_rewrite_rule(
            RewriteContext {
                target_root: root.into(),
            },
            &pending.id,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("evidence changed after planning"));
        assert_eq!(
            serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
            before
        );
        assert_eq!(fs::read(&policy_path).unwrap(), policy);
        let result = crate::rewrite::recover_rewrite_rule_plan(
            RewriteContext {
                target_root: root.into(),
            },
            &pending.id,
        )
        .unwrap();
        assert_eq!(result["applied"], false);
        assert_eq!(result["status"], "fresh_replay_required");
        let recovered = store.load().unwrap().unwrap();
        assert!(
            recovered.rule_plan.is_none()
                && recovered.rule_replay_pending
                && !recovered.e2e_current
        );
        assert_eq!(fs::read(policy_path).unwrap(), policy);
    }
}

#[test]
fn legacy_generated_plan_is_recoverable_and_cannot_be_silently_refrozen() {
    let mut f = fixture();
    let root = f.target.path();
    f.state
        .rule_plan
        .as_mut()
        .unwrap()
        .generated_witnesses
        .clear();
    let id = f.state.rule_plan.as_ref().unwrap().id.clone();
    let store = RewriteStore::new(root).unwrap();
    store.save(&f.state).unwrap();
    let before = serde_json::to_value(&f.state).unwrap();
    let policy_path = root.join(".traffic-e2e/verification.yaml");
    let policy = fs::read(&policy_path).unwrap();
    assert!(plan(root, &mut f.state, f.options.clone()).is_err());
    assert!(
        crate::rewrite::apply_rewrite_rule(
            RewriteContext {
                target_root: root.into()
            },
            &id
        )
        .is_err()
    );
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
    let result = crate::rewrite::recover_rewrite_rule_plan(
        RewriteContext {
            target_root: root.into(),
        },
        &id,
    )
    .unwrap();
    assert_eq!(result["status"], "fresh_replay_required");
    assert_eq!(result["applied"], false);
    let recovered = store.load().unwrap().unwrap();
    assert!(
        recovered.rule_plan.is_none() && recovered.rule_replay_pending && !recovered.e2e_current
    );
    assert_eq!(fs::read(policy_path).unwrap(), policy);
}

#[test]
fn signed_pending_plan_checks_current_key_and_recovers_after_rotation_without_writing() {
    for rotated in [false, true] {
        let mut f = jwt_fixture();
        let root = f.target.path();
        let pending = f.state.rule_plan.as_ref().unwrap().clone();
        let policy_path = root.join(".traffic-e2e/verification.yaml");
        let policy = fs::read(&policy_path).unwrap();
        let before = serde_json::to_value(&f.state).unwrap();
        if rotated {
            fs::write(
                root.join(".traffic-e2e/local/target.env"),
                "SECRET_KEY=rotated-key\n",
            )
            .unwrap();
        }
        GeneratedValueRulePlan::ensure_evidence_current(&pending.generated_witnesses).unwrap();
        let context = || RewriteContext {
            target_root: root.into(),
        };
        if rotated {
            assert!(crate::rewrite::rule::generated_evidence_stale(
                root, &f.state, &pending
            ));
            assert!(plan(root, &mut f.state, f.options.clone()).is_err());
            assert_eq!(serde_json::to_value(&f.state).unwrap(), before);
            assert!(crate::rewrite::apply_rewrite_rule(context(), &pending.id).is_err());
            let store = RewriteStore::new(root).unwrap();
            assert_eq!(
                serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
                before
            );
            let result = crate::rewrite::recover_rewrite_rule_plan(context(), &pending.id).unwrap();
            assert_eq!(result["status"], "fresh_replay_required");
            assert_eq!(result["applied"], false);
            let recovered = store.load().unwrap().unwrap();
            assert!(
                recovered.rule_plan.is_none()
                    && recovered.rule_replay_pending
                    && !recovered.e2e_current
            );
            assert_eq!(fs::read(&policy_path).unwrap(), policy);
            assert!(!result.to_string().contains("fixture-signing-key"));
            assert!(!result.to_string().contains("rotated-key"));
        } else {
            assert!(!crate::rewrite::rule::generated_evidence_stale(
                root, &f.state, &pending
            ));
            assert!(crate::rewrite::recover_rewrite_rule_plan(context(), &pending.id).is_err());
            let result = crate::rewrite::apply_rewrite_rule(context(), &pending.id).unwrap();
            assert_eq!(result.traffic_e2e_report["applied"], true);
            assert_eq!(result.traffic_e2e_report["requires_fresh_replay"], true);
        }
    }
}

#[test]
fn missing_signed_report_can_recover_but_never_during_an_active_attempt() {
    for report in ["assertions", "aggregate"] {
        for active in [false, true] {
            let f = jwt_fixture();
            let root = f.target.path();
            let pending = f.state.rule_plan.as_ref().unwrap();
            let missing = if report == "assertions" {
                &f.evidence.assertions
            } else {
                &f.evidence.aggregate
            };
            fs::remove_file(missing).unwrap();
            if active {
                fs::create_dir(
                    f.evidence
                        .replay
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .join(".active"),
                )
                .unwrap();
            }
            let store = RewriteStore::new(root).unwrap();
            let before = serde_json::to_value(&f.state).unwrap();
            let policy_path = root.join(".traffic-e2e/verification.yaml");
            let policy = fs::read(&policy_path).unwrap();
            let result = crate::rewrite::recover_rewrite_rule_plan(
                RewriteContext {
                    target_root: root.into(),
                },
                &pending.id,
            );
            if active {
                assert!(format!("{:#}", result.unwrap_err()).contains("active"));
                assert_eq!(
                    serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
                    before
                );
            } else {
                let result = result.unwrap();
                assert_eq!(result["status"], "fresh_replay_required");
                assert_eq!(result["applied"], false);
                let recovered = store.load().unwrap().unwrap();
                assert!(
                    recovered.rule_plan.is_none()
                        && recovered.rule_replay_pending
                        && !recovered.e2e_current
                );
            }
            assert_eq!(fs::read(policy_path).unwrap(), policy);
        }
    }
}
