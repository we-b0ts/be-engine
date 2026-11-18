//! One registered value policy runs on protocol-owned locations through a single executor.
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
use traffic_contract::{codec::Codec, rule::FieldContract};
use traffic_policy_value::{PreparedMessage, RuleBinding, ValueRule};
use traffic_protocol::{
    connection::NativeProtocol, evidence::MessageSide, message::ProtocolMessage,
};

#[test]
fn the_same_registered_policy_compares_http_redis_and_mysql_values() {
    let rule = Arc::new(ValueRule {
        id: "collection".into(),
        contract: serde_json::from_value::<FieldContract>(json!({
            "kind":"policy", "id":"unordered-joined-string", "version":1,
            "options":{"separator":","}
        }))
        .unwrap(),
    });
    for (target, passes) in [("red,red,blue", true), ("red,blue", false)] {
        let source = "red,blue,red";
        let http = |value: &str| {
            Arc::new(traffic_protocol_http::message::RequestMessage {
                method: "GET".into(),
                uri: "/items".into(),
                body: bytes::Bytes::new(),
                headers: BTreeMap::from([("x-values".into(), vec![value.to_owned()])]),
            }) as Arc<dyn ProtocolMessage>
        };
        let redis = |value: &str| {
            Arc::new(traffic_protocol_redis::message::RequestMessage {
                command: "SET".into(),
                args: vec!["values".into(), value.to_owned().into()],
                resp_version: 2,
                database: 0,
                username: None,
            }) as Arc<dyn ProtocolMessage>
        };
        let mysql = |value: &str| {
            let witness = json!({
                "request":{"command":"COM_QUERY", "sql":"SELECT value FROM items"},
                "outcome":"response", "response":{
                    "status":"resultset", "columns":[{
                        "name":"value", "database":"app", "table":"items", "column":"value",
                        "family":"string", "sql_type":"VARCHAR"
                    }], "rows":[[{"kind":"string", "value":value}]]
                }
            });
            traffic_protocol_mysql::native::Native
                .decode_evidence(
                    &json!({"database":"app"}),
                    &serde_json::to_vec(&witness).unwrap(),
                    MessageSide::Response,
                )
                .unwrap()
                .response
                .unwrap()
        };
        for (protocol, before, after, selector) in [
            (
                "http",
                http(source),
                http(target),
                json!({"kind":"header", "name":"x-values"}),
            ),
            (
                "redis",
                redis(source),
                redis(target),
                json!({"kind":"value"}),
            ),
            (
                "mysql",
                mysql(source),
                mysql(target),
                json!({"kind":"field", "table":"items", "column":"value"}),
            ),
        ] {
            let prepared = PreparedMessage::compile(
                before.as_ref(),
                &[RuleBinding {
                    rule: rule.clone(),
                    selector,
                    codec: Codec::Scalar,
                    pointer: String::new(),
                }],
                traffic_extensions::codecs(),
            )
            .unwrap();
            let comparison = prepared
                .compare(
                    after.as_ref(),
                    Default::default(),
                    &crate::value_contract::json::PolicyMetadata,
                )
                .unwrap();
            assert_eq!(comparison.passed(), passes, "{protocol} {comparison:?}");
        }
    }
}
