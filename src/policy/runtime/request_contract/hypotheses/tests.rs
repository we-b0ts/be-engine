use super::*;
use crate::protocols::replay::mysql::RecordedMysqlExchange;
use crate::protocols::replay::mysql::{RecordedMysqlValue, ReplaySessionIdentity};
use serde_json::json;

const A: &str = "11111111-1111-4111-8111-111111111111";
const B: &str = "22222222-2222-4222-8222-222222222222";
const C: &str = "33333333-3333-4333-8333-333333333333";

fn runtime() -> RequestContracts {
    let mut owner = RequestContracts::default();
    owner
        .configure_compiled(Some(Arc::new(
            crate::policy::parse_and_compile_policy(
                "format: traffic-policy/v3\njson:\n  fields: {}\n",
            )
            .unwrap(),
        )))
        .unwrap();
    owner.configure_pre_match(true);
    owner.state.lock().unwrap().cases.insert(
        "case".into(),
        CaseAnchor {
            method: "POST".into(),
            path: "/jobs".into(),
            source_uri: "/jobs".into(),
            source_input_error: None,
            source_body: None,
            conditions: Default::default(),
            recorded: DateTime::from_timestamp(1700000000, 0),
            actual: DateTime::from_timestamp(1700000010, 0),
            dir: PathBuf::new(),
            dependencies_path: PathBuf::new(),
        },
    );
    owner
}

fn record(sql: &str) -> RecordedMysqlExchange {
    serde_json::from_value(json!({"command":"COM_QUERY","sql":sql,"connection_id":uuid::Uuid::new_v4(),"query_sequence":1,"target_host":"db.test","target_port":3306,"database":"app","timestamp":"2023-11-14T22:13:20Z","response":{"status":"ok","affected_rows":1}})).unwrap()
}

fn identity() -> ReplaySessionIdentity {
    ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.test".into(),
            port: 3306,
        }),
        database: Some("app".into()),
        username: None,
    }
}

#[test]
fn hypothesis_failed_json_candidate_keeps_all_considered_leaf_rules() {
    let owner = runtime();
    let before = json!({"a_id":A,"b_time":"2023-11-14T22:13:20Z","c_business":1}).to_string();
    let after = json!({"a_id":B,"b_time":"not a timestamp","c_business":2}).to_string();
    let clocks = crate::value_contract::json::AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: DateTime::from_timestamp(1700000000, 0),
            target: DateTime::from_timestamp(1700000010, 0),
        },
        ..Default::default()
    };
    let preview = crate::value_contract::hypothesis::preview_json(
        "case",
        before.as_bytes(),
        after.as_bytes(),
        owner.global_json().unwrap(),
        clocks,
    );
    assert!(owner.retain_hypothesis_preview(preview).is_none());
    let attempts = owner.hypothesis_attempts();
    assert_eq!(attempts.len(), 1);
    assert!(attempts.iter().all(|a| a.status == "rejected"));
    assert_eq!(
        attempts.iter().filter(|a| a.validation == "passed").count(),
        1
    );
    let output = serde_json::to_string(&attempts).unwrap();
    assert!(!output.contains(A) && !output.contains(B) && !output.contains("not a timestamp"));
    assert!(owner.pre_match_reports().is_empty());
}

#[test]
fn hypothesis_sql_prepared_json_and_redis_key_share_one_staged_identity() {
    let owner = runtime();
    let source = record(&format!(
        "INSERT INTO jobs (id,payload,created_at) VALUES ('{A}','{{\"id\":\"{A}\"}}',1700000000)"
    ));
    let params:Vec<RecordedMysqlValue>=serde_json::from_value(json!([{ "kind":"string","value":B},{"kind":"string","value":format!("{{\"id\":\"{B}\"}}")},{"kind":"integer","value":1700000010}])).unwrap();
    let decision = owner
        .preview_mysql_hypothesis(
            "case",
            &identity(),
            &source,
            "COM_STMT_EXECUTE",
            Some("INSERT INTO jobs (id,payload,created_at) VALUES (?,?,?)"),
            Some(&params),
            DateTime::from_timestamp(1700000010, 0).unwrap(),
            Some(uuid::Uuid::new_v4()),
            None,
        )
        .unwrap()
        .unwrap_or_else(|error| panic!("{error:#}; attempts={:?}", owner.hypothesis_attempts()));
    assert!(
        !owner.has_identities("case"),
        "candidate preview must not commit identity"
    );
    for decision in decision.value_contracts {
        owner.commit(decision).unwrap();
    }
    assert!(
        owner
            .knows_identity_value("case", &json!(A), &json!(B))
            .unwrap()
    );
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, "SET");
    context.recorded_at = DateTime::from_timestamp(1700000000, 0);
    context.actual_at = DateTime::from_timestamp(1700000010, 0);
    let args = |id: &str| {
        vec![
            format!("job:{id}:state").into_bytes(),
            json!({"id":id}).to_string().into_bytes(),
        ]
    };
    owner
        .commit(
            owner
                .preview_redis_hypothesis(&context, &args(A), &args(B))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    assert!(
        owner
            .hypothesis_attempts()
            .iter()
            .any(|a| a.carrier == "redis_key" && a.status == "selected")
    );
    assert!(
        owner
            .preview_redis_hypothesis(&context, &args(A), &args(C))
            .unwrap()
            .is_err(),
        "same Source identity cannot change its Target correspondence"
    );
}

#[test]
fn hypothesis_sql_structure_and_redis_options_remain_strict() {
    let owner = runtime();
    let source = record(&format!("UPDATE jobs SET id='{A}' WHERE tenant=7"));
    let changed = format!("UPDATE other_jobs SET id='{B}' WHERE tenant=7");
    assert!(
        owner
            .preview_mysql_hypothesis(
                "case",
                &identity(),
                &source,
                "COM_QUERY",
                Some(&changed),
                None,
                DateTime::from_timestamp(1700000010, 0).unwrap(),
                None,
                None
            )
            .unwrap()
            .is_err()
    );
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let context = RedisRequestContext::without_exchange("case", &target, 0, "SET");
    let args = |id: &str, option: &str| {
        vec![
            format!("job:{id}").into_bytes(),
            b"same".to_vec(),
            option.as_bytes().to_vec(),
        ]
    };
    assert!(
        owner
            .preview_redis_hypothesis(&context, &args(A, "NX"), &args(B, "XX"))
            .unwrap()
            .is_err()
    );
    assert!(
        owner
            .hypothesis_attempts()
            .iter()
            .any(|a| a.carrier == "redis_key")
    );
    assert!(owner.pre_match_reports().is_empty());
}

#[test]
fn builtin_sql_time_composes_with_a_real_uuid_hypothesis_without_a_time_hint() {
    for (date, passes) in [
        ("2023-11-14T22:13:30Z", true),
        ("2023-11-14T22:13:30.000Z", false),
        ("2023-11-14T22:13:39Z", false),
    ] {
        let owner = runtime();
        let source = record(&format!(
            "INSERT INTO jobs (id,created_at) VALUES ('{A}','2023-11-14T22:13:20Z')"
        ));
        let params: Vec<RecordedMysqlValue> = serde_json::from_value(json!([
            {"kind":"string","value":B}, {"kind":"string","value":date}
        ]))
        .unwrap();
        let decision = owner
            .preview_mysql_hypothesis(
                "case",
                &identity(),
                &source,
                "COM_STMT_EXECUTE",
                Some("INSERT INTO jobs (id,created_at) VALUES (?,?)"),
                Some(&params),
                DateTime::from_timestamp(1700000010, 0).unwrap(),
                None,
                None,
            )
            .unwrap();
        assert_eq!(decision.is_ok(), passes, "{date}");
        if let Ok(decision) = decision {
            let hints = decision
                .value_contracts
                .iter()
                .flat_map(|decision| &decision.pre_matches)
                .collect::<Vec<_>>();
            assert_eq!(hints.len(), 1);
            assert!(hints[0].draft_policy.to_string().contains("identity"));
            assert!(decision.value_contracts.iter().any(|decision| {
                decision
                    .ids
                    .iter()
                    .any(|id| id == crate::value_contract::time::automatic::RULE_ID)
            }));
        }
        let attempts = owner.hypothesis_attempts();
        assert_eq!(attempts.len(), 1, "builtin time never produces a rule hint");
        assert!(
            attempts[0]
                .candidate
                .draft_policy
                .to_string()
                .contains("identity")
        );
    }
}

#[test]
fn builtin_redis_argument_composes_with_a_real_key_hypothesis_and_stays_strict() {
    for (date, passes) in [
        ("2023-11-14T22:13:30Z", true),
        ("2023-11-14T22:13:30.000Z", false),
        ("2023-11-14T22:13:39Z", false),
    ] {
        let owner = runtime();
        let target = TargetKey {
            host: "cache.test".into(),
            port: 6379,
        };
        let mut context = RedisRequestContext::without_exchange("case", &target, 0, "MSET");
        context.recorded_at = DateTime::from_timestamp(1700000000, 0);
        context.actual_at = DateTime::from_timestamp(1700000010, 0);
        let args = |id: &str, date: &str| {
            vec![
                format!("job:{id}").into_bytes(),
                b"same".to_vec(),
                b"clock".to_vec(),
                date.as_bytes().to_vec(),
            ]
        };
        let result = owner
            .preview_redis_hypothesis(&context, &args(A, "2023-11-14T22:13:20Z"), &args(B, date))
            .unwrap();
        assert_eq!(result.is_ok(), passes, "{date}");
        if let Ok(decision) = result {
            assert_eq!(decision.pre_matches.len(), 1);
            assert!(
                decision
                    .ids
                    .iter()
                    .any(|id| id == crate::value_contract::time::automatic::RULE_ID)
            );
        }
        let attempts = owner.hypothesis_attempts();
        assert_eq!(attempts.len(), 1, "builtin time never produces a rule hint");
        assert_eq!(attempts[0].carrier, "redis_key");
    }
}

#[test]
fn scalar_root_owners_prevent_time_hypotheses_and_builtin_reclassification() {
    let owner = runtime();
    let mut configured = owner.clone();
    configured.configure_compiled(Some(Arc::new(crate::policy::parse_and_compile_policy(
        "format: traffic-policy/v3\njson:\n  fields:\n    '': {kind: identity, formats: [uuid]}\n",
    ).unwrap()))).unwrap();
    let source = record(&format!(
        "INSERT INTO jobs (stamp,id) VALUES (1700000000,'{A}')"
    ));
    let params: Vec<RecordedMysqlValue> = serde_json::from_value(json!([
        {"kind":"integer","value":1700000010}, {"kind":"string","value":B}
    ]))
    .unwrap();
    assert!(
        configured
            .preview_mysql_hypothesis(
                "case",
                &identity(),
                &source,
                "COM_STMT_EXECUTE",
                Some("INSERT INTO jobs (stamp,id) VALUES (?,?)"),
                Some(&params),
                DateTime::from_timestamp(1700000010, 0).unwrap(),
                None,
                None,
            )
            .unwrap()
            .is_err()
    );
    assert!(configured.hypothesis_attempts().is_empty());

    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, "MSET");
    context.recorded_at = DateTime::from_timestamp(1700000000, 0);
    context.actual_at = DateTime::from_timestamp(1700000010, 0);
    let args = |id: &str, date: &str| {
        vec![
            b"clock".to_vec(),
            date.as_bytes().to_vec(),
            format!("job:{id}").into_bytes(),
            b"same".to_vec(),
        ]
    };
    assert!(
        configured
            .preview_redis_hypothesis(
                &context,
                &args(A, "2023-11-14T22:13:20Z"),
                &args(B, "2023-11-14T22:13:30Z"),
            )
            .unwrap()
            .is_err()
    );
    assert!(configured.hypothesis_attempts().is_empty());
}

#[test]
fn mysql_hypotheses_keep_mixed_precision_clocks_independent_per_value_slot() {
    for json_payload in [false, true] {
        let owner = runtime();
        let (source_sql, target_sql, params) = if json_payload {
            let payload = |id: &str, at: &str| json!({"id":id,"at":at}).to_string();
            (
                format!(
                    "INSERT INTO jobs (left_value,right_value) VALUES ('{}','{}')",
                    payload(A, "2023-11-14T22:13:20Z"),
                    payload(A, "2023-11-14T22:13:20.123Z")
                ),
                "INSERT INTO jobs (left_value,right_value) VALUES (?,?)",
                json!([{"kind":"string","value":payload(B, "2023-11-14T22:13:30Z")},{"kind":"string","value":payload(B, "2023-11-14T22:13:30.579Z")}]),
            )
        } else {
            (
                format!(
                    "INSERT INTO jobs (id,whole,milli) VALUES ('{A}','2023-11-14T22:13:20Z','2023-11-14T22:13:20.123Z')"
                ),
                "INSERT INTO jobs (id,whole,milli) VALUES (?,?,?)",
                json!([{"kind":"string","value":B},{"kind":"string","value":"2023-11-14T22:13:30Z"},{"kind":"string","value":"2023-11-14T22:13:30.579Z"}]),
            )
        };
        let params: Vec<RecordedMysqlValue> = serde_json::from_value(params).unwrap();
        let decision = owner
            .preview_mysql_hypothesis(
                "case",
                &identity(),
                &record(&source_sql),
                "COM_STMT_EXECUTE",
                Some(target_sql),
                Some(&params),
                DateTime::from_timestamp(1700000010, 456_789_000).unwrap(),
                None,
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            decision
                .value_contracts
                .iter()
                .map(|decision| decision.pre_matches.len())
                .sum::<usize>(),
            if json_payload { 2 } else { 1 }
        );
        assert!(owner.hypothesis_attempts().iter().all(|attempt| {
            attempt
                .candidate
                .draft_policy
                .to_string()
                .contains("identity")
        }));
    }
}

#[test]
fn redis_hypotheses_keep_mixed_precision_clocks_independent_per_argument() {
    for json_payload in [false, true] {
        let owner = runtime();
        let target = TargetKey {
            host: "cache.test".into(),
            port: 6379,
        };
        let mut context = RedisRequestContext::without_exchange("case", &target, 0, "MSET");
        context.recorded_at = DateTime::from_timestamp(1700000000, 0);
        context.actual_at = DateTime::from_timestamp(1700000010, 456_789_000);
        let args = |id: &str, whole: &str, milli: &str| {
            if json_payload {
                vec![
                    b"first".to_vec(),
                    json!({"id":id,"at":whole}).to_string().into_bytes(),
                    b"second".to_vec(),
                    json!({"id":id,"at":milli}).to_string().into_bytes(),
                ]
            } else {
                vec![
                    format!("job:{id}").into_bytes(),
                    b"same".to_vec(),
                    b"whole".to_vec(),
                    whole.as_bytes().to_vec(),
                    b"milli".to_vec(),
                    milli.as_bytes().to_vec(),
                ]
            }
        };
        let decision = owner
            .preview_redis_hypothesis(
                &context,
                &args(A, "2023-11-14T22:13:20Z", "2023-11-14T22:13:20.123Z"),
                &args(B, "2023-11-14T22:13:30Z", "2023-11-14T22:13:30.579Z"),
            )
            .unwrap()
            .unwrap();
        assert_eq!(decision.pre_matches.len(), if json_payload { 2 } else { 1 });
        assert!(owner.hypothesis_attempts().iter().all(|attempt| {
            attempt
                .candidate
                .draft_policy
                .to_string()
                .contains("identity")
        }));
    }
}

#[tokio::test]
async fn hypothesis_journal_acknowledges_authenticated_decisions_before_delivery() {
    let temporary = tempfile::tempdir().unwrap();
    let journal = crate::policy_evidence::hypotheses::Journal::create(
        temporary.path().join("attempts.jsonl"),
        vec![7; 32],
    )
    .unwrap();
    journal
        .append(&json!({"kind":"hypothesis_attempt","status":"rejected"}))
        .unwrap();
    journal
        .append(&json!({"kind":"hypothesis_selected","attempt_id":"one"}))
        .unwrap();
    journal.wait_durable().await.unwrap();
    let manifest = journal.manifest();
    assert!(manifest.complete);
    assert_eq!(manifest.durable, 2);
    let bytes = std::fs::read_to_string(temporary.path().join(manifest.path)).unwrap();
    let rows: Vec<Value> = bytes
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["sequence"], 2);
    assert!(rows.iter().all(|row| {
        row["authentication"]
            .as_str()
            .is_some_and(|a| !a.is_empty())
    }));
}

#[test]
fn stopped_journal_preserves_rejected_hints_and_prevents_unsafe_delivery() {
    let temporary = tempfile::tempdir().unwrap();
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let journal = executor.block_on(async {
        crate::policy_evidence::hypotheses::Journal::create(
            temporary.path().join("stopped.jsonl"),
            vec![3; 32],
        )
        .unwrap()
    });
    drop(executor);
    let mut owner = runtime();
    owner.hypothesis_journal = Some(journal);
    let before = json!({"id":A});
    let after = json!({"id":B});
    let preview = crate::value_contract::hypothesis::preview_values(
        "case",
        &before,
        &after,
        owner.global_json().unwrap(),
        Default::default(),
    );
    assert!(owner.retain_hypothesis_preview(preview).is_none());
    assert_eq!(owner.hypothesis_attempts().len(), 1);
    assert!(owner.hypothesis_coverage_error().is_some());
    assert!(owner.pre_match_reports().is_empty());
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert!(executor.block_on(owner.await_hypotheses_durable()).is_err());
    assert!(!owner.hypothesis_journal_manifest().unwrap().complete);
}

#[tokio::test]
async fn journal_cannot_acknowledge_a_missing_protected_payload() {
    let temporary = tempfile::tempdir().unwrap();
    let journal = crate::policy_evidence::hypotheses::Journal::create(
        temporary.path().join("missing-payload.jsonl"),
        vec![5; 32],
    )
    .unwrap();
    journal
        .append_with_protected_files(
            &json!({"kind":"hypothesis_witness"}),
            vec![temporary.path().join("missing-witness.jsonl")],
        )
        .unwrap();
    assert!(journal.wait_durable().await.is_err());
    let manifest = journal.manifest();
    assert_eq!(manifest.durable, 0);
    assert!(!manifest.complete);
    assert!(manifest.error.is_some());
}

#[tokio::test]
async fn later_hypotheses_must_still_persist_a_previously_published_payload_segment() {
    let temporary = tempfile::tempdir().unwrap();
    let payload = temporary.path().join("protected.jsonl");
    std::fs::write(&payload, b"protected observation\n").unwrap();
    let journal = crate::policy_evidence::hypotheses::Journal::create(
        temporary.path().join("attempts.jsonl"),
        vec![5; 32],
    )
    .unwrap();
    journal
        .append_with_protected_files(&json!({"attempt":1}), vec![payload.clone()])
        .unwrap();
    journal.wait_durable().await.unwrap();
    std::fs::remove_file(&payload).unwrap();
    journal
        .append_with_protected_files(&json!({"attempt":2}), vec![payload])
        .unwrap();
    assert!(journal.wait_durable().await.is_err());
    let manifest = journal.manifest();
    assert_eq!(manifest.durable, 1);
    assert_eq!(manifest.enqueued, 2);
    assert!(!manifest.complete);
}
