//! Request predicates preserve generated/forwarded branches and initialization/touch ownership.
use super::*;

fn request(event: Option<&str>) -> Value {
    json!({"method":"POST","uri":"/events","timestamp":"1970-01-01T00:16:40Z",
        "body":{"encoding":"utf8","truncated":false,"data":json!({"event_type":event}).to_string()}})
}

fn time_rule(id: &str, operator: &str, fields: &[&str]) -> Value {
    let fields: serde_json::Map<String, Value> = fields
        .iter()
        .map(|field| {
            (
                (*field).into(),
                json!({"time":"preserve_relative","format":"unix_seconds"}),
            )
        })
        .collect();
    json!({"id":id,"protocol":"redis","case":{"method":"POST","path":"/events"},
        "when":{"request_body_json":{"/event_type":{operator:"session.started"}}},
        "target":{"host":"cache.test","port":6379},
        "source_evidence":"Session:start initializes both clocks; touch preserves the start clock",
        "redis":{"database":0,"key":"session:1","commands":[{"command":"SET","argument_values":{"1":{"json":fields}}}]}})
}

#[test]
fn disjoint_inbound_branches_select_initialization_without_relaxing_touches() {
    let document = json!({"version":3,"expected_response":"assertions_only","dependency_rules":[
        time_rule("start", "equals", &["/started_at","/last_activity_at"]),
        time_rule("touch", "not_equals", &["/last_activity_at"])
    ]});
    let fixture = policy_fixture(&serde_yaml::to_string(&document).unwrap());
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let args = |start, last| {
        vec![
            b"session:1".to_vec(),
            json!({"started_at":start,"last_activity_at":last,"user":7})
                .to_string()
                .into_bytes(),
        ]
    };
    for (event, start, last, expected) in [
        (Some("session.started"), 2000, 2000, Some(true)),
        (Some("session.started"), 2001, 2000, Some(false)),
        (Some("session.touched"), 1000, 2000, Some(true)),
        (Some("session.touched"), 2000, 2000, Some(false)),
        (None, 2000, 2000, None),
    ] {
        fs::write(
            fixture.cases[CASE_ID].dir.join("request.json"),
            request(event).to_string(),
        )
        .unwrap();
        let runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
        runtime.request_contracts.set_request_times(
            CASE_ID,
            crate::replay::assertion::RequestTimes {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
        );
        let decision = runtime.request_contracts.preview_redis(
            CASE_ID,
            &target,
            0,
            "SET",
            &args(1000, 1000),
            &args(start, last),
        );
        assert_eq!(decision.map(|result| result.is_ok()), expected, "{event:?}");
    }
}

#[test]
fn generated_capture_cannot_bind_fixed_input_or_missing_inbound_discriminator() {
    let document = json!({"version":3,"expected_response":"assertions_only","dependency_rules":[{
        "kind":"dynamic_value",
        "id":"generated-id","api":"/events","targets":[{"host":"cache.test","port":6379}],
        "when":{"request_body_json":{"/event_type":{"equals":"delta"}}},
        "capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},"database":0,
            "command":"RPUSH","key":"events:1","argument_index":1,"json_pointer":"/id"},
        "source_evidence":"Emitter:delta generates a new identity; created forwards the inbound identity"
    }]});
    let fixture = policy_fixture(&serde_yaml::to_string(&document).unwrap());
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let args = |id| {
        vec![
            b"events:1".to_vec(),
            json!({"id":id,"kind":"text"}).to_string().into_bytes(),
        ]
    };
    for (event, selected) in [
        (Some("delta"), true),
        (Some("created"), false),
        (None, false),
    ] {
        fs::write(
            fixture.cases[CASE_ID].dir.join("request.json"),
            request(event).to_string(),
        )
        .unwrap();
        let runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
        assert_eq!(
            runtime
                .dynamic_values
                .redis(
                    Some(CASE_ID),
                    &target,
                    0,
                    "RPUSH",
                    &args("old"),
                    &args("new")
                )
                .is_some(),
            selected
        );
    }
}
