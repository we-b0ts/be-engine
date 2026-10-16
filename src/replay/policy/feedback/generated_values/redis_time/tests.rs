use super::*;
use crate::replay::policy::feedback::tests::RetiredFixture;
struct Fixture {
    files: RetiredFixture,
    identity: DynamicValueRule,
    time: DynamicValueRedisTimeRule,
}
impl Fixture {
    fn new(command: &str) -> Self {
        let identity=serde_json::from_value(json!({"id":"item-id","api":"/items","targets":[{"host":"cache.test","port":6379}],"when":{"request_body_json":{"/mode":{"equals":"generated"}}},"capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},"database":0,"command":command,"key":{"prefix":"items:","numeric":true},"argument_index":1,"json_pointer":"/id","references":[{"json_pointer":"/content_key","template":"cache:payload:{key_middle}:{value}"}],"derived_from":{"json_pointer":"/timestamp","prefix":"item-"}},"source_evidence":"src/items.rs binds the generated identity and its exact copied payload references"})).unwrap();
        Self {
            files: RetiredFixture::new(),
            identity,
            time: DynamicValueRedisTimeRule {
                id: "item-time".into(),
                method: "POST".into(),
                time_values: vec![RedisJsonTimeValueSelector {
                    json_pointer: "/timestamp".into(),
                    format: "unix_milliseconds".into(),
                }],
                source_evidence: "src/items.rs records request-relative current milliseconds"
                    .into(),
            },
        }
    }
}
#[test]
fn retired_joint_redis_plan_rejects_set_and_rpush_without_touching_evidence() {
    for command in ["SET", "RPUSH"] {
        let fixture = Fixture::new(command);
        fixture.files.check(|| {
            plan_dynamic_value_redis_time_rule(
                DynamicValueRuleFeedback {
                    policy_path: fixture.files.policy.clone(),
                    rule: fixture.identity.clone(),
                    replay_report: fixture.files.evidence.clone(),
                },
                fixture.time.clone(),
            )
        });
    }
}
#[test]
fn redis_time_companion_preserves_explicit_nonoverlapping_field_ownership() {
    let mut fixture = Fixture::new("SET");
    let proposed = fixture.time.proposed(&fixture.identity).unwrap();
    assert_eq!(proposed.id, "item-time");
    fixture.time.time_values[0].json_pointer = "/content_key".into();
    assert!(fixture.time.proposed(&fixture.identity).is_err());
    fixture.time.time_values[0].json_pointer = "/id".into();
    assert!(fixture.time.proposed(&fixture.identity).is_err());
}

#[test]
fn redis_json_reference_ownership_cannot_mask_another_capture_validation() {
    let fixture = Fixture::new("SET");
    let mut left = fixture.identity.clone();
    if let DynamicValueCapture::Redis {
        json_pointer,
        references,
        derived_from,
        ..
    } = &mut left.capture
    {
        *json_pointer = Some("/a".into());
        *derived_from = None;
        *references = Some(vec![crate::RedisCaptureReference {
            json_pointer: "/b".into(),
            template: "{value}".into(),
        }]);
    }
    let mut right = left.clone();
    right.id = "uuid-field".into();
    right.format = Some(crate::DynamicValueFormat::UuidV4);
    if let DynamicValueCapture::Redis {
        json_pointer,
        references,
        ..
    } = &mut right.capture
    {
        *json_pointer = Some("/b".into());
        *references = Some(vec![]);
    }
    // A first rule must not rewrite /b before the second rule validates its
    // original Target UUID. Either order has identical ownership rejection.
    assert!(
        crate::replay::policy::dynamic_values::validate(&[left.clone(), right.clone()]).is_err()
    );
    assert!(
        crate::replay::policy::dynamic_values::validate(&[right.clone(), left.clone()]).is_err()
    );
    right.when = Some(
        serde_json::from_value(json!({"request_body_json":{"/mode":{"equals":"forwarded"}}}))
            .unwrap(),
    );
    assert!(crate::replay::policy::dynamic_values::validate(&[left, right]).is_ok());
}
