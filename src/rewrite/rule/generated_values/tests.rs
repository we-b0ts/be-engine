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
