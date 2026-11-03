//! Actual sealed observations distinguish declaration drift from absent provenance.
use super::*;
use crate::recorder::{CaseContext, Recorder, capture_body};
use crate::rewrite::{RewriteContext, dependency_attribution_context, store::RewriteStore};

fn policy(key: &str) -> CompiledPolicy {
    crate::policy::parse_and_compile_policy(&format!(
        "format: traffic-policy/v3\nasync_api:\n  'POST /jobs':\n    when_response: {{/status: queued}}\n    end:\n      - redis: {{operation: DEL, key: '{key}', occurrence: 2}}\n"
    ))
    .unwrap()
}

fn observation(policy: &CompiledPolicy) -> Value {
    json!({"version":2,"api":"POST /jobs","scenario_index":0,
        "policy_provenance":AsyncRuleProvenance::selected("POST /jobs",&policy.async_api["POST /jobs"],0).unwrap()})
}

#[test]
fn same_rule_different_rule_and_removed_rule_are_distinct_declaration_facts() {
    let before = policy("private-before:*");
    let after = policy("private-after:*");
    let actual = observation(&before);
    let same = compare(serde_json::from_value(actual.clone()).unwrap(), &before).unwrap();
    assert_eq!(same.status, "same_rule");
    assert_eq!(same.scenario_status, "same_scenario_at_recorded_index");
    assert!(same.unknown_reason.is_none());
    let changed = compare(serde_json::from_value(actual.clone()).unwrap(), &after).unwrap();
    assert_eq!(changed.status, "different_rule");
    assert_eq!(
        changed.scenario_status,
        "different_scenario_at_recorded_index"
    );
    let absent = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\n").unwrap();
    let removed = compare(serde_json::from_value(actual).unwrap(), &absent).unwrap();
    assert_eq!(removed.status, "current_rule_absent");
    assert_eq!(removed.scenario_status, "current_scenario_absent");
    let public = serde_json::to_string(&changed).unwrap();
    assert!(!public.contains("private-before"));
    assert!(!public.contains("private-after"));
}

#[test]
fn old_missing_receipts_and_unknown_versions_do_not_claim_policy_application_time() {
    let current = policy("done:*");
    for (provenance, reason) in [
        (Value::Null, "recorded_rule_provenance_unavailable"),
        (
            json!({"version":99,"future":"ignored"}),
            "unsupported_recorded_provenance_version",
        ),
    ] {
        let actual = Observation {
            api: "POST /jobs".into(),
            scenario_index: Some(0),
            policy_provenance: Some(provenance),
        };
        let result = compare(actual, &current).unwrap();
        assert_eq!(result.status, "unknown");
        assert_eq!(result.scenario_status, "unknown");
        assert_eq!(result.unknown_reason, Some(reason));
        assert!(result.recorded_rule_fingerprint.is_none());
        assert!(result.current_rule_fingerprint.is_some());
    }
    let old: Observation = serde_json::from_value(json!({
        "version":1,"api":"POST /jobs","end_reason":"resource"
    }))
    .unwrap();
    let result = compare(old, &current).unwrap();
    assert_eq!(result.status, "unknown");
    assert!(result.scenario_index.is_none());
}

#[test]
fn changed_sibling_scenario_does_not_claim_the_recorded_scenario_changed() {
    let before = policy("done:*");
    let mut after = before.clone();
    after.async_api.get_mut("POST /jobs").unwrap().0.push(
        serde_json::from_value(json!({"when_response":{"/status":"other"},"end":[{
            "http":{"method":"POST","endpoint":"worker.test:80","path":"/complete"}
        }]}))
        .unwrap(),
    );
    let result = compare(
        serde_json::from_value(observation(&before)).unwrap(),
        &after,
    )
    .unwrap();
    assert_eq!(result.status, "different_rule");
    assert_eq!(result.scenario_status, "same_scenario_at_recorded_index");
}

#[test]
fn contradictory_receipt_scenario_is_rejected_instead_of_compared_as_current() {
    let current = policy("done:*");
    let mut actual = observation(&current);
    actual["policy_provenance"]["scenario_index"] = json!(1);
    assert!(compare(serde_json::from_value(actual).unwrap(), &current).is_err());
}

#[tokio::test]
async fn public_context_compares_only_sealed_observations_and_rejects_changed_receipts() {
    let target = crate::rewrite::worker::tests::configured_target();
    let current = policy("private-current:*");
    fs::write(
        target.path().join(".traffic-e2e/policy.yaml"),
        "format: traffic-policy/v3\nasync_api:\n  'POST /jobs':\n    when_response: {/status: queued}\n    end:\n      - redis: {operation: DEL, key: 'private-current:*', occurrence: 2}\n",
    )
    .unwrap();
    let recorder = Recorder::new(target.path().join(".traffic-e2e/local/recordings"))
        .await
        .unwrap();
    let mut observation_path = None;
    for actual in [
        Some(observation(&current)),
        Some(observation(&policy("private-old:*"))),
        Some(json!({"version":2,"api":"POST /jobs","scenario_index":0})),
        None,
    ] {
        let case = CaseContext {
            id: uuid::Uuid::new_v4(),
            rule_name: "jobs".into(),
            uri_group: None,
        };
        for (name, value) in [
            ("admission.json", json!({"fixture":true})),
            (
                "request.json",
                json!({"method":"POST","uri":"/jobs","body":capture_body(b"{}",16)}),
            ),
            (
                "expected-response.json",
                json!({"status":200,"body":capture_body(br#"{"status":"queued"}"#,64)}),
            ),
        ] {
            recorder.write_case_json(&case, name, &value).await.unwrap();
        }
        if let Some(actual) = actual {
            recorder
                .write_case_json(&case, OBSERVATION_FILE, &actual)
                .await
                .unwrap();
            observation_path = Some(recorder.case_dir(&case).join(OBSERVATION_FILE));
        }
        recorder.publish_case(&case).await.unwrap();
    }
    recorder.finish_run().await.unwrap();
    let mut state = crate::rewrite::test_support::test_state();
    state.case_source = Some(recorder.run_dir.as_ref().clone());
    state.recording_run_id = recorder
        .run_dir
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .into();
    state.source_revision = Some(format!("sha256:{}", "a".repeat(64)));
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let context = || RewriteContext {
        target_root: target.path().into(),
    };
    let actual = dependency_attribution_context(context())
        .unwrap()
        .async_capture_policy;
    assert_eq!(actual["complete_inputs"], 4);
    assert_eq!(actual["inputs_with_async_observation"], 3);
    assert_eq!(actual["inputs_without_async_observation"], 1);
    let statuses = actual["groups"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["status"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(statuses, ["same_rule", "different_rule", "unknown"].into());
    let public = serde_json::to_string(&actual).unwrap();
    assert!(!public.contains("private-current"));
    assert!(!public.contains("private-old"));
    fs::write(observation_path.unwrap(), b"{}").unwrap();
    assert!(dependency_attribution_context(context()).is_err());
}
