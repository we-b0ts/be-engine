use std::{collections::BTreeMap, sync::Arc};

use bytes::Bytes;
use serde_json::{Value, json};
use traffic_contract::{
    codec::Codec,
    compare::{AnchorClocks, Comparison, ExplicitRules},
    rule::{FieldContract, IdentityFormat},
};
use traffic_protocol::message::{MessageEncoder, ProtocolMessage};
use traffic_replay::rules::{PreparedMessage, RuleBinding, ValueRule};

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
    let http = PreparedMessage::compile(&http(source), &bindings)
        .unwrap()
        .compare(&http(target), AnchorClocks::default(), &ExplicitRules)
        .unwrap();
    let bindings = [
        binding(rule, json!({"kind":"key"}), Codec::Scalar, ""),
        binding(rule, json!({"kind":"hash_field"}), Codec::Scalar, ""),
        binding(rule, json!({"kind":"value"}), Codec::Json, "/owner"),
    ];
    let redis = PreparedMessage::compile(&redis(source), &bindings)
        .unwrap()
        .compare(&redis(target), AnchorClocks::default(), &ExplicitRules)
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
    let mysql = PreparedMessage::compile(&mysql(source), &bindings)
        .unwrap()
        .compare(&mysql(target), AnchorClocks::default(), &ExplicitRules)
        .unwrap();
    vec![http, redis, mysql]
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
    let plan = PreparedMessage::compile(
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
                .compare(&actual, AnchorClocks::default(), &ExplicitRules)
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
    let plan = PreparedMessage::compile(
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
            .compare(&http("id_1011"), AnchorClocks::default(), &ExplicitRules)
            .unwrap()
            .passed()
    );
}

#[test]
fn common_delivery_validation_returns_values_to_the_native_encoder_and_evidence_owner() {
    let source = redis("id_11");
    let rule = rule();
    let plan = PreparedMessage::compile(
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
        .render_values(&updates, AnchorClocks::default(), &ExplicitRules)
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
        plan.render_values(&invalid, AnchorClocks::default(), &ExplicitRules)
            .is_err()
    );
    invalid = updates;
    invalid.insert("/args/1".into(), json!("id_1012"));
    assert!(
        plan.render_values(&invalid, AnchorClocks::default(), &ExplicitRules)
            .is_err()
    );
    let evidence = source.evidence(&json!({"kind":"hash_field"})).unwrap();
    assert_eq!(evidence["arguments"][0]["location"], "/args/1");
}
