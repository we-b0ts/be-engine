use super::*;
use crate::policy::{Proof, compile_native};
use serde_json::json;

fn event() -> serde_json::Value {
    let capture = |text: &str| json!({"encoding":"utf8","data":text,"truncated":false,"original_len":text.len(),"stored_len":text.len()});
    json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,"target_host":"cache.test","database":0,"target_port":6379,"command":"SCARD","args":[capture("session")],
        "replay_safe":true,"session_setup":false,"outcome":"response","response":capture(":1\r\n")})
}
fn case(root: &Path, name: &str, event: &serde_json::Value) -> PathBuf {
    let path = root.join("GET-api").join(name);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(
        path.join("request.json"),
        json!({"method":"GET","uri":"/api","timestamp":"2026-10-17T00:00:00Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(path.join("expected-response.json"), "{}").unwrap();
    std::fs::write(path.join("dependencies.jsonl"), event.to_string()).unwrap();
    path
}
fn rule() -> CompiledNativeRule {
    compile_native(&n::NativeRule {
        id: "refresh-session".into(),
        selector: Default::default(),
        when: None,
        proof: Proof {
            source: "src/cache:refresh".into(),
            fact: "The process refreshes this exact key independently of APIs".into(),
        },
        effect: n::NativeEffect::ProcessOwned(n::ProcessOwnedEffect {
            source_revision: String::new(),
            origin: None,
            selector: n::ProcessSelector::Redis {
                ports: vec![6379],
                operation: "SCARD".into(),
                keys: vec![n::NativeKeySelector::Exact {
                    value: "session".into(),
                }],
                key_templates: vec![],
                key_sequence: vec![],
                arguments: vec![],
                script: None,
                initial_load_timeout_ms: Some(1000),
                fields: vec![],
            },
        }),
    })
    .unwrap()
}

#[test]
fn source_scope_reenumerates_foreign_cases_and_global_members_and_binds_the_run_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("run-one");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(
        root.join("recording-run.json"),
        json!({"run_id":"run-one","status":"completed"}).to_string(),
    )
    .unwrap();
    let first = case(&root, "case-a", &event());
    let prepared = BTreeMap::from([("case-a".into(), first)]);
    let validate = |run| {
        validate_source(
            NativeSourceScope {
                target_root: temp.path(),
                case_source: &root,
                source_revision: "unused-for-data-only-effect",
                recording_run_id: run,
                prepared_cases: &prepared,
                replay_report: &root.join("report.json"),
                policy_rules: &[rule()],
            },
            &[rule()],
        )
    };
    let before = validate("run-one").unwrap();
    assert_eq!(before.rules["refresh-session"], 1);
    assert_eq!(
        before.obligations,
        BTreeSet::from([SourceObligation::Reclassify])
    );
    case(&root, "case-b", &event());
    let after = validate("run-one").unwrap();
    assert_eq!(after.rules["refresh-session"], 2);
    assert_ne!(before.inventory.digest, after.inventory.digest);
    std::fs::write(root.join("global-dependencies.jsonl"), event().to_string()).unwrap();
    let global = validate("run-one").unwrap();
    assert_eq!(global.rules["refresh-session"], 3);
    assert_ne!(after.inventory.digest, global.inventory.digest);
    assert!(validate("another-run").is_err());
}

#[test]
fn source_ownership_cannot_prove_truncated_or_inconsistent_capture_lengths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("run-one");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(
        root.join("recording-run.json"),
        json!({"run_id":"run-one","status":"completed"}).to_string(),
    )
    .unwrap();
    let first = case(&root, "case-a", &event());
    let prepared = BTreeMap::from([("case-a".into(), first.clone())]);
    for field in ["truncated", "stored_len"] {
        let mut event = event();
        event["response"][field] = if field == "truncated" {
            json!(true)
        } else {
            json!(999)
        };
        std::fs::write(first.join("dependencies.jsonl"), event.to_string()).unwrap();
        assert!(
            validate_source(
                NativeSourceScope {
                    target_root: temp.path(),
                    case_source: &root,
                    source_revision: "data-fact",
                    recording_run_id: "run-one",
                    prepared_cases: &prepared,
                    replay_report: &root.join("report.json"),
                    policy_rules: &[rule()],
                },
                &[rule()]
            )
            .is_err()
        );
    }
}
