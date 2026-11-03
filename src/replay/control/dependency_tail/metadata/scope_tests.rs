use super::*;
use crate::dependency::observation::{SCOPE_SCHEMA, ScopeIndex, ScopeKind, ScopeRecordLocation};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[tokio::test]
async fn derived_idle_scope_requires_actual_inventory_without_requiring_a_missing_end() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case-a");
    std::fs::create_dir(&case_dir).unwrap();
    std::fs::write(temp.path().join("recording-run.json"), "{}").unwrap();
    std::fs::write(
        case_dir.join("request.json"),
        json!({"method":"POST","uri":"/jobs",
            "body":{"encoding":"utf8","data":"{}","truncated":false}})
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        case_dir.join("expected-response.json"),
        json!({"status":200,
            "body":{"encoding":"utf8","data":"{}","truncated":false}})
        .to_string(),
    )
    .unwrap();
    let original = Uuid::new_v4();
    let added = Uuid::new_v4();
    let row = format!(
        "{}\n",
        json!({"event_type":"http_exchange","id":added,"outcome":"response",
            "method":"POST","uri":"/work","authority":"executor.test",
            "scheme":"http","response_status":200})
    );
    std::fs::write(temp.path().join("dependencies.jsonl"), &row).unwrap();
    let scope_path = case_dir.join("effective-scope.json");
    std::fs::write(
        &scope_path,
        serde_json::to_vec(&ScopeIndex {
            schema: SCOPE_SCHEMA.into(),
            run_relpath: "..".into(),
            scope: ScopeKind::Case {
                case_id: Uuid::new_v4(),
            },
            locations: vec![ScopeRecordLocation {
                line: 1,
                offset: 0,
                length: row.len() as u64,
                sha256: format!("{:x}", Sha256::digest(row.as_bytes())),
                exchange_id: added,
                effect_index: 0,
            }],
        })
        .unwrap(),
    )
    .unwrap();
    let rules = BTreeMap::from([(
        "POST /jobs".into(),
        serde_json::from_value(json!({"end":[{
            "http":{"method":"POST","endpoint":"executor.test:80","path":"/done"}
        }]}))
        .unwrap(),
    )]);
    let observation = case_dir.join("async-api-observation.json");
    for reason in [
        "idle",
        "resource",
        "probe",
        "stopped",
        "timeout",
        "dependency_failure",
    ] {
        let stopped = matches!(reason, "stopped" | "timeout" | "dependency_failure");
        std::fs::write(
            &observation,
            json!({
                "version":2,"request_timeout_ms":1000,
                "capture_complete":true,"inventory_complete":true,
                "business_complete":reason=="resource",
                "business_completion":if reason=="resource" {"observed"} else {"unobserved"},
                "end_reason":if reason=="probe" {"resource"} else {reason},
                "ending":(reason=="probe").then(|| json!({"reason":"probe_completed",
                    "probe_ms":1000,"started_after_ms":1,"elapsed_ms":1001})),
                "idle_completion":(reason=="idle").then(|| json!({"quiet_ms":300_000})),
                "source_stop_required":stopped,
                "source_stop_after_ms":stopped.then_some(1000),
                "completed_refs":[{"protocol":"http","exchange_id":original}]
            })
            .to_string(),
        )
        .unwrap();
        let result = load_effective(&case_dir, &scope_path, &rules, Duration::from_secs(1)).await;
        if reason != "idle" {
            let error = result.err().unwrap();
            assert!(
                error.to_string().contains("no proven completion"),
                "{reason}: {error}"
            );
            continue;
        }
        let metadata = result.unwrap().unwrap();
        assert!(metadata.normal_completion);
        assert!(!metadata.source_stop_required);
        assert!(!metadata.failure_completion);
        let expected = RecordedReference::Http { exchange_id: added };
        assert_eq!(metadata.references, [expected], "{reason}");
        assert_eq!(
            metadata.strict_references,
            BTreeSet::from([expected]),
            "{reason}"
        );
        let saved_scope = std::fs::read(&scope_path).unwrap();
        let mut duplicate_scope: ScopeIndex = serde_json::from_slice(&saved_scope).unwrap();
        let mut duplicate = duplicate_scope.locations[0].clone();
        duplicate.line = 2;
        duplicate.offset = row.len() as u64;
        duplicate_scope.locations.push(duplicate);
        std::fs::write(temp.path().join("dependencies.jsonl"), row.repeat(2)).unwrap();
        std::fs::write(&scope_path, serde_json::to_vec(&duplicate_scope).unwrap()).unwrap();
        let error = load_effective(&case_dir, &scope_path, &rules, Duration::from_secs(1))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("repeats an exchange"), "{error}");
        std::fs::write(temp.path().join("dependencies.jsonl"), &row).unwrap();
        std::fs::write(&scope_path, saved_scope).unwrap();
    }
    let prior_failure = std::fs::read(&observation).unwrap();
    std::fs::remove_file(&observation).unwrap();
    let error = load_effective(&case_dir, &scope_path, &rules, Duration::from_secs(1))
        .await
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("no proven completion"),
        "{error}"
    );
    // Existing failed captures can still be recovered by a corrected scope
    // that actually proves its declared end, while retaining Source-stop facts.
    std::fs::write(observation, prior_failure).unwrap();
    let complete_row = row.replace("/work", "/done");
    std::fs::write(temp.path().join("dependencies.jsonl"), &complete_row).unwrap();
    let mut scope: ScopeIndex =
        serde_json::from_slice(&std::fs::read(&scope_path).unwrap()).unwrap();
    scope.locations[0].sha256 = format!("{:x}", Sha256::digest(complete_row.as_bytes()));
    std::fs::write(&scope_path, serde_json::to_vec(&scope).unwrap()).unwrap();
    let repaired = load_effective(&case_dir, &scope_path, &rules, Duration::from_secs(1))
        .await
        .unwrap()
        .unwrap();
    assert!(repaired.normal_completion);
    assert!(repaired.source_stop_required);
    assert_eq!(repaired.source_stop_after_ms, Some(1000));
}
