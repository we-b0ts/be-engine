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
