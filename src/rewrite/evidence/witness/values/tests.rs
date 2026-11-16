use super::*;
use anyhow::{Context, Result};
use serde_json::json;
use std::{borrow::Cow, sync::Arc};
use traffic_protocol::evidence::{EvidenceSecrets, MessageSide, ValueQuery};
use traffic_value::codec::{
    CodecDescriptor, CodecProvider, Recognition, ValueCodec, ValueDocument,
};

struct Secrets;
impl EvidenceSecrets for Secrets {
    fn unseal_text<'a>(&self, _: &str, value: &'a str) -> Result<Cow<'a, str>> {
        Ok(Cow::Borrowed(value))
    }
}

fn observed(
    event: &serde_json::Value,
    side: MessageSide,
    pointer: &str,
    index: usize,
) -> serde_json::Value {
    let providers = crate::protocols::default_providers();
    let owner = providers.event_provider(event).unwrap();
    let payload = providers
        .evidence()
        .source_payload(owner.kind.as_str(), event, side, &Secrets)
        .unwrap()
        .unwrap();
    let query = ValueQuery {
        side,
        pointer,
        value_index: index,
    };
    let result = providers
        .evidence()
        .query_value(
            event,
            &payload,
            query,
            &Reader(traffic_extensions::codecs()),
        )
        .unwrap()
        .unwrap();
    serde_json::to_value(result.observation).unwrap()
}

#[test]
fn redis_native_payload_selection_reaches_the_shared_reader_for_requests_and_responses() {
    let capture = |value| json!({"encoding":"utf8", "data":value, "truncated":false});
    let mut event = json!({"event_type":"redis_exchange", "command":"HSET",
        "args":[capture("cache"),capture("first"),capture("{\"value\":1}"),capture("second"),capture("{\"value\":2}")]});
    assert_eq!(
        observed(&event, MessageSide::Request, "/value", 1),
        json!({"presence":"present", "value":2})
    );
    event["command"] = json!("HGET");
    event["args"] = json!([capture("cache"), capture("first")]);
    event["response"] = capture("$11\r\n{\"value\":3}\r\n");
    assert_eq!(
        observed(&event, MessageSide::Response, "/value", 0),
        json!({"presence":"present", "value":3})
    );
    event["command"] = json!("PUBLISH");
    event["args"] = json!([capture("channel"), capture("{\"value\":4}")]);
    assert_eq!(
        observed(&event, MessageSide::Request, "/value", 0),
        json!({"presence":"present", "value":4})
    );
}

#[test]
fn mysql_native_cell_queries_retain_missing_unavailable_and_native_context() {
    let sql = "INSERT INTO items(payload) VALUES('observed')";
    let event = json!({"event_type":"mysql_exchange", "connection_id":uuid::Uuid::nil(), "query_sequence":1,
        "command":"COM_QUERY", "database":"app", "sql":sql, "response":{"status":"ok"}});
    let position = traffic_protocol_mysql::sql::bounds::statement(sql)
        .unwrap()
        .iter()
        .position(|token| matches!(token, traffic_protocol_mysql::sql::Token::Bytes(_)))
        .unwrap();
    let pointer = format!("/sql_values/{position}/field/table");
    assert_eq!(
        observed(&event, MessageSide::Request, &pointer, 0),
        json!({"presence":"present","value":"items"})
    );
    assert_eq!(
        observed(
            &event,
            MessageSide::Request,
            &format!("/sql_values/{position}/value"),
            0
        ),
        json!({"presence":"present","value":"observed"})
    );
    assert_eq!(
        observed(
            &event,
            MessageSide::Response,
            &format!("/request/sql_values/{position}/value"),
            0
        ),
        json!({"presence":"present","value":"observed"})
    );
    assert_eq!(
        observed(&event, MessageSide::Request, "/sql_values/0/value", 0)["presence"],
        "missing"
    );
    assert_eq!(
        observed(
            &event,
            MessageSide::Request,
            "/sql_values/not-an-index/value",
            0
        )["presence"],
        "unavailable"
    );
}

#[test]
fn logical_reader_preserves_null_missing_and_bounded_unavailable_observations() {
    let reader = Reader(traffic_extensions::codecs());
    let observed =
        |bytes: &[u8], pointer| serde_json::to_value(reader.select(bytes, pointer)).unwrap();
    assert_eq!(
        observed(br#"{"value":null}"#, "/value"),
        json!({"presence":"present","value":null})
    );
    assert_eq!(
        observed(br#"{"value":null}"#, "/other"),
        json!({"presence":"missing"})
    );
    assert_eq!(
        observed(&vec![b'x'; 4 * 1024 * 1024 + 1], "/value")["presence"],
        "unavailable"
    );
    let large = json!({"value":"x".repeat(4097)});
    assert_eq!(
        observed(&serde_json::to_vec(&large).unwrap(), "/value")["presence"],
        "unavailable"
    );
}

struct CustomCodec;
impl CodecProvider for CustomCodec {
    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: "fixture",
            version: 1,
        }
    }
    fn recognize(&self, bytes: &[u8], _: &Value) -> Result<Recognition> {
        Ok(if bytes.starts_with(b"fixture:") {
            Recognition::Recognized {
                confidence: 1,
                configuration: Value::Null,
            }
        } else {
            Recognition::Unrecognized
        })
    }
    fn prepare(&self, _: &Value) -> Result<Arc<dyn ValueCodec>> {
        Ok(Arc::new(CustomCodec))
    }
}
struct Document {
    original: Vec<u8>,
    value: Value,
}
impl ValueCodec for CustomCodec {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        let value = std::str::from_utf8(bytes)?
            .strip_prefix("fixture:")
            .context("fixture prefix absent")?;
        Ok(Arc::new(Document {
            original: bytes.to_vec(),
            value: Value::Object(std::collections::BTreeMap::from([(
                "value".into(),
                Value::String(value.into()),
            )])),
        }))
    }
}
impl ValueDocument for Document {
    fn value(&self) -> &Value {
        &self.value
    }
    fn original_bytes(&self) -> &[u8] {
        &self.original
    }
    fn comparison_view<'a>(&'a self, _: &[String]) -> Cow<'a, Value> {
        Cow::Borrowed(&self.value)
    }
    fn encode(&self, _: &Value, _: &[String]) -> Result<Vec<u8>> {
        anyhow::bail!("read-only fixture")
    }
}

#[test]
fn registering_a_codec_extends_native_witness_selection_without_changing_the_reader() {
    let mut codecs = CodecRegistry::default();
    codecs.register(Arc::new(CustomCodec)).unwrap();
    assert_eq!(
        serde_json::to_value(Reader(&codecs).select(b"fixture:observed", "/value")).unwrap(),
        json!({"presence":"present","value":"observed"})
    );
    assert_eq!(
        serde_json::to_value(
            Reader(&CodecRegistry::default()).select(b"fixture:observed", "/value")
        )
        .unwrap()["presence"],
        "unavailable"
    );
}

#[test]
fn http_native_body_queries_use_the_same_installed_value_reader() {
    let capture = |value| json!({"encoding":"utf8", "data":value, "truncated":false});
    let event = json!({"event_type":"http_exchange", "scheme":"http", "authority":"service.test:8080", "id":"http-observation",
        "method":"POST", "uri":"/items", "request_headers":{}, "request_body":capture("{\"value\":1}"),
        "response_status":200, "response_headers":{}, "response_body":capture("{\"value\":2}")});
    assert_eq!(
        observed(&event, MessageSide::Request, "/value", 0),
        json!({"presence":"present","value":1})
    );
    assert_eq!(
        observed(&event, MessageSide::Response, "/value", 0),
        json!({"presence":"present","value":2})
    );
    assert_eq!(
        observed(&event, MessageSide::Response, "/value", 1)["presence"],
        "unavailable"
    );
}

#[test]
fn native_sql_cells_delegate_embedded_content_to_the_registered_codec_reader() {
    let event = json!({"event_type":"mysql_exchange", "command":"COM_QUERY", "database":"app",
        "sql":"SELECT 'fixture:observed'", "response":{"status":"ok"}});
    let payload =
        traffic_protocol_mysql::witness::source_payload(&event, MessageSide::Request).unwrap();
    let mut codecs = CodecRegistry::default();
    codecs.register(Arc::new(CustomCodec)).unwrap();
    let providers = crate::protocols::default_providers();
    let result = providers
        .evidence()
        .query_value(
            &event,
            &payload,
            ValueQuery {
                side: MessageSide::Request,
                value_index: 0,
                pointer: "/sql_values/1/json/value",
            },
            &Reader(&codecs),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(result.observation).unwrap(),
        json!({"presence":"present","value":"observed"})
    );
}
