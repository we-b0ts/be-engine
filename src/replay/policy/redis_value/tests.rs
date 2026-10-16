use super::super::config::{LoadedReplayPolicy, load_replay_policy};
use anyhow::Result;
use serde_json::{Value, json};

fn load(rule: Value) -> Result<LoadedReplayPolicy> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("policy.yaml");
    let policy = json!({"version": 3, "expected_response": "assertions_only",
        "dependency_rules": [rule]});
    crate::replay::write_policy_fixture(&path, serde_yaml::to_string(&policy)?)?;
    load_replay_policy(&path)
}

fn legacy_rule(selector: Value) -> Value {
    json!({"id": "legacy-rule", "protocol": "redis",
        "target": {"host": "cache.test", "port": 6379}, "redis": selector})
}

fn condition() -> Value {
    json!({"request_body_json": {"/event_type": {"equals": "session.created"}}})
}

fn assert_rule_retains_condition(mut rule: Value) {
    load(rule.clone()).expect("the typed selector must remain valid");
    rule["when"] = condition();
    let loaded = load(rule).expect("Source conditions remain in the compiled guard");
    let compiled = loaded.compiled.unwrap();
    assert!(
        compiled.rules.iter().any(|rule| rule.rule.when.is_some())
            || compiled.native.iter().any(|rule| rule.rule.when.is_some())
    );
}

#[test]
fn unordered_value_rules_remain_valid_but_retain_source_conditions() {
    assert_rule_retains_condition(legacy_rule(json!({
        "key": "items:7", "unordered": [{
            "field": {"codec": "json", "pointer": "/items"},
            "source_evidence": "Store:members returns a set whose iteration order is unspecified"
        }]
    })));
}

#[test]
fn lock_token_rules_remain_valid_but_retain_source_conditions() {
    assert_rule_retains_condition(legacy_rule(json!({"lock": {
        "key": "lock:7",
        "source_evidence": "Lock:acquire generates a token reused by its matching release"
    }})));
}

#[test]
fn publish_rules_remain_valid_but_retain_source_conditions() {
    assert_rule_retains_condition(legacy_rule(json!({"publish": {
        "channel": "events", "uuid_field": "publisher_id",
        "source_evidence": "Publisher:start generates a UUID reused for its published events"
    }})));
}

#[test]
fn response_time_shift_rules_remain_valid_but_retain_source_conditions() {
    assert_rule_retains_condition(legacy_rule(json!({
        "command": "GET", "key": "session:7", "response_json": {
            "/expires_at": {"time": "preserve_relative", "format": "unix_milliseconds"}
        }
    })));
}

#[test]
fn argument_request_contracts_continue_to_accept_source_conditions() {
    let mut rule = legacy_rule(json!({
        "database": 0, "key": "session:7", "commands": [{
            "command": "SET", "argument_values": {"1": {"json": {
                "/updated_at": {"time": "preserve_relative", "format": "unix_seconds"}
            }}}
        }]
    }));
    rule["case"] = json!({"method": "POST", "path": "/sessions"});
    rule["source_evidence"] =
        json!("Session:update writes the current request-relative update time");
    for operator in ["equals", "not_equals"] {
        let mut predicate = serde_json::Map::new();
        predicate.insert(operator.into(), json!("session.created"));
        rule["when"] = json!({"request_body_json": {"/event_type": predicate}});
        load(rule.clone()).expect("request contracts retain conditional rule support");
    }
}
