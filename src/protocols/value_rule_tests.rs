use std::{collections::BTreeMap, sync::Arc};

use crate::value_contract::json::PolicyMetadata;
use bytes::Bytes;
use serde_json::{Value, json};
use traffic_contract::{
    codec::Codec,
    compare::{AnchorClocks, Comparison, ExplicitRules},
    rule::{FieldContract, IdentityFormat},
};
use traffic_policy_value::{RuleBinding, ValueRule};
use traffic_protocol::message::{MessageEncoder, ProtocolMessage};

fn rule() -> Arc<ValueRule> {
    Arc::new(ValueRule {
        id: "generated-resource-id".into(),
        contract: FieldContract::Identity {
            prefix: "id_".into(),
            format: IdentityFormat::Decimal,
        },
    })
}

fn binding(rule: &Arc<ValueRule>, selector: Value, codec: Codec, pointer: &str) -> RuleBinding {
    RuleBinding {
        rule: rule.clone(),
        selector,
        codec,
        pointer: pointer.into(),
    }
}

fn http(id: &str) -> traffic_protocol_http::message::RequestMessage {
    traffic_protocol_http::message::RequestMessage {
        method: "POST".into(),
        uri: format!("/items/{id}?mode=full"),
        headers: BTreeMap::from([("x-project".into(), vec!["stable".into()])]),
        body: serde_json::to_vec(&json!({"owner":id,"stable":1}))
            .unwrap()
            .into(),
    }
}

fn redis(id: &str) -> traffic_protocol_redis::message::RequestMessage {
    traffic_protocol_redis::message::RequestMessage {
        command: "HSET".into(),
        resp_version: 2,
        database: 3,
        username: None,
        args: vec![
            Bytes::copy_from_slice(id.as_bytes()),
            Bytes::copy_from_slice(id.as_bytes()),
            serde_json::to_vec(&json!({"owner":id,"stable":1}))
                .unwrap()
                .into(),
        ],
    }
}

fn mysql(id: &str) -> traffic_protocol_mysql::message::RequestMessage {
    traffic_protocol_mysql::message::RequestMessage {
        command: "COM_STMT_EXECUTE".into(),
        database: Some("app".into()),
        username: None,
        sql: Some(format!("UPDATE users SET id = ? WHERE owner = '{id}'")),
        params: Some(vec![traffic_protocol_mysql::model::MysqlValue {
            kind: "string".into(),
            value: Some(json!(id)),
            raw: None,
        }]),
    }
}

fn comparisons(rule: &Arc<ValueRule>, source: &str, target: &str) -> Vec<Comparison> {
    let bindings = [
        binding(
            rule,
            json!({"kind":"path_segment","index":1}),
            Codec::Scalar,
            "",
        ),
        binding(rule, json!({"kind":"body"}), Codec::Json, "/owner"),
    ];
    let http = crate::value_extensions::prepare_message(&http(source), &bindings)
        .unwrap()
        .compare(&http(target), AnchorClocks::default(), &PolicyMetadata)
        .unwrap();
    let bindings = [
        binding(rule, json!({"kind":"key"}), Codec::Scalar, ""),
        binding(rule, json!({"kind":"hash_field"}), Codec::Scalar, ""),
        binding(rule, json!({"kind":"value"}), Codec::Json, "/owner"),
    ];
    let redis = crate::value_extensions::prepare_message(&redis(source), &bindings)
        .unwrap()
        .compare(&redis(target), AnchorClocks::default(), &PolicyMetadata)
        .unwrap();
    let bindings = [
        binding(
            rule,
            json!({"kind":"field","table":"users","column":"id"}),
            Codec::Json,
            "",
        ),
        binding(
            rule,
            json!({"kind":"field","table":"users","column":"owner"}),
            Codec::Json,
            "",
        ),
    ];
    let mysql = crate::value_extensions::prepare_message(&mysql(source), &bindings)
        .unwrap()
        .compare(&mysql(target), AnchorClocks::default(), &PolicyMetadata)
        .unwrap();
    vec![http, redis, mysql]
}

fn duration_messages(elapsed: i64, stable: i64) -> Vec<(Box<dyn ProtocolMessage>, Value)> {
    let value = json!({"elapsed":elapsed,"stable":stable});
    let mut http = http("fixed");
    http.body = serde_json::to_vec(&value).unwrap().into();
    let mut redis = redis("fixed");
    redis.args[2] = serde_json::to_vec(&value).unwrap().into();
    let mut mysql = mysql("fixed");
    let parameter = &mut mysql.params.as_mut().unwrap()[0];
    parameter.kind = "json".into();
    parameter.value = Some(value);
    vec![
        (Box::new(http), json!({"kind":"body"})),
        (Box::new(redis), json!({"kind":"value"})),
        (
            Box::new(mysql),
            json!({"kind":"field","table":"users","column":"id"}),
        ),
    ]
}

#[test]
fn registered_policy_definitions_execute_at_existing_http_redis_and_mysql_entrypoints() {
    let rule = Arc::new(ValueRule {
        id: "elapsed".into(),
        contract: serde_json::from_value(json!({"kind":"policy","id":"duration","version":1,
            "options":{"unit":"seconds","clock":"dependency"}}))
        .unwrap(),
    });
    let clocks = AnchorClocks {
        dependency: traffic_contract::time::ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    };
    for (((source, selector), (target, _)), (changed, _)) in duration_messages(10, 1)
        .into_iter()
        .zip(duration_messages(1010, 1))
        .zip(duration_messages(1010, 2))
    {
        let bindings = [binding(&rule, selector, Codec::Json, "/elapsed")];
        let prepared =
            crate::value_extensions::prepare_message(source.as_ref(), &bindings).unwrap();
        let metadata = crate::value_contract::json::PolicyMetadata;
        let result = prepared
            .compare(target.as_ref(), clocks, &metadata)
            .unwrap();
        assert!(result.passed(), "{:?}", result.differences);
        assert!(result.evaluated.contains("elapsed"));
        assert!(
            !prepared
                .compare(changed.as_ref(), clocks, &metadata)
                .unwrap()
                .passed()
        );
        assert!(
            !prepared
                .compare(target.as_ref(), AnchorClocks::default(), &metadata)
                .unwrap()
                .passed()
        );
        assert!(
            !prepared
                .compare(target.as_ref(), clocks, &ExplicitRules)
                .unwrap()
                .passed()
        );
    }
}

#[test]
fn one_rule_executes_at_http_redis_and_mysql_locations_with_shared_identity_proposals() {
    let rule = rule();
    let mut result = Comparison::default();
    for comparison in comparisons(&rule, "id_11", "id_1011") {
        assert!(comparison.passed(), "{:?}", comparison.differences);
        assert!(comparison.evaluated.contains(&rule.id));
        result.merge_and_validate(comparison);
    }
    assert!(result.passed());
    assert_eq!(result.identity_pairs().len(), 1);
    let mut conflicting = Comparison::default();
    conflicting.merge_and_validate(comparisons(&rule, "id_11", "id_1011").remove(0));
    conflicting.merge_and_validate(comparisons(&rule, "id_11", "id_1012").remove(1));
    assert!(!conflicting.passed());
}

#[test]
fn native_structure_unselected_values_and_conditional_branches_remain_strict() {
    let rule = rule();
    let plan = crate::value_extensions::prepare_message(
        &http("id_11"),
        &[
            binding(
                &rule,
                json!({"kind":"path_segment","index":1}),
                Codec::Scalar,
                "",
            ),
            binding(&rule, json!({"kind":"body"}), Codec::Json, "/owner"),
        ],
    )
    .unwrap();
    for mutation in ["method", "query", "body", "header", "missing", "format"] {
        let mut actual = http("id_1011");
        match mutation {
            "method" => actual.method = "DELETE".into(),
            "query" => actual.uri.push_str("&extra=1"),
            "body" => actual.body = Bytes::from_static(br#"{"owner":"id_1011","stable":2}"#),
            "header" => actual.headers.get_mut("x-project").unwrap()[0] = "changed".into(),
            "missing" => actual.body = Bytes::from_static(br#"{"stable":1}"#),
            _ => actual.uri = "/items/id_bad?mode=full".into(),
        }
        assert!(
            !plan
                .compare(&actual, AnchorClocks::default(), &PolicyMetadata)
                .unwrap()
                .passed(),
            "{mutation}"
        );
    }
    let conditional = Arc::new(ValueRule {
        id: "conditional".into(),
        contract: serde_json::from_value(
            json!({"kind":"conditional", "when":{"relative_pointer":"../stable","equals":2},
            "contract":{"kind":"identity","prefix":"id_","format":"decimal"}}),
        )
        .unwrap(),
    });
    let plan = crate::value_extensions::prepare_message(
        &http("id_11"),
        &[
            binding(
                &rule,
                json!({"kind":"path_segment","index":1}),
                Codec::Scalar,
                "",
            ),
            binding(&conditional, json!({"kind":"body"}), Codec::Json, "/owner"),
        ],
    )
    .unwrap();
    assert!(
        !plan
            .compare(&http("id_1011"), AnchorClocks::default(), &PolicyMetadata)
            .unwrap()
            .passed()
    );
}

#[test]
fn common_delivery_validation_returns_values_to_the_native_encoder_and_evidence_owner() {
    let source = redis("id_11");
    let rule = rule();
    let plan = crate::value_extensions::prepare_message(
        &source,
        &[
            binding(&rule, json!({"kind":"key"}), Codec::Scalar, ""),
            binding(&rule, json!({"kind":"hash_field"}), Codec::Scalar, ""),
            binding(&rule, json!({"kind":"value"}), Codec::Json, "/owner"),
        ],
    )
    .unwrap();
    let updates = BTreeMap::from([
        ("/args/0".into(), json!("id_1011")),
        ("/args/1".into(), json!("id_1011")),
        ("/args/2".into(), json!({"owner":"id_1011","stable":1})),
    ]);
    let values = plan
        .render_values(&updates, AnchorClocks::default(), &PolicyMetadata)
        .unwrap();
    let encoded = source.encode(&values).unwrap();
    let actual = traffic_protocol_redis::redis_command(&encoded).unwrap();
    assert_eq!(actual.name, "HSET");
    assert_eq!(actual.args[0], b"id_1011");
    assert_eq!(actual.args[1], b"id_1011");
    assert_eq!(
        serde_json::from_slice::<Value>(&actual.args[2]).unwrap(),
        json!({"owner":"id_1011","stable":1})
    );
    let mut invalid = updates.clone();
    invalid.insert("/args/2".into(), json!({"owner":"id_1011","stable":2}));
    assert!(
        plan.render_values(&invalid, AnchorClocks::default(), &PolicyMetadata)
            .is_err()
    );
    invalid = updates;
    invalid.insert("/args/1".into(), json!("id_1012"));
    assert!(
        plan.render_values(&invalid, AnchorClocks::default(), &PolicyMetadata)
            .is_err()
    );
    let evidence = source.evidence(&json!({"kind":"hash_field"})).unwrap();
    assert_eq!(evidence["arguments"][0]["location"], "/args/1");
}
