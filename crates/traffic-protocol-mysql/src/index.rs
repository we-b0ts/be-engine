//! Compact SQL selectors and bounded legacy decoding, without storage access.
use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn fingerprint(sql: &str) -> String {
    let hash = sql.bytes().fold(0xcbf29ce484222325_u64, |hash, b| {
        (hash ^ u64::from(b)).wrapping_mul(0x100000001b3)
    });
    format!("fnv1a64:{hash:016x}")
}

pub fn summary(value: &Value) -> Option<Value> {
    if value["event_type"] != "mysql_exchange" {
        return None;
    }
    Some(summarize(value))
}
fn summarize(value: &Value) -> Value {
    let sql = value["sql"].as_str().unwrap_or_default();
    let tokens = crate::sql::tokens(sql);
    let integer_hashes: Option<Vec<_>> = tokens.as_ref().map(|tokens| {
        tokens
            .iter()
            .filter_map(|token| match token {
                crate::sql::Token::Number(number) => Some(digest(number.as_bytes())),
                _ => None,
            })
            .collect()
    });
    json!({"target_host":value["target_host"],"target_port":value["target_port"],
            "database":value["database"],"username":value["username"],"command":value["command"],
            "sql_token_count":tokens.map(|tokens| tokens.len()),"integer_hashes":integer_hashes,
            "connection_id":value["connection_id"],"query_sequence":value["query_sequence"],
            "server_status_before":value["server_status_before"],"server_status_after":value["response"]["server_status"],
            "sql_summary":{"fingerprint":fingerprint(sql)}})
}

pub fn summary_from_raw(raw: &[u8]) -> Result<Option<Value>> {
    let facts: SqlRecord = serde_json::from_slice(raw)?;
    if facts.event_type != "mysql_exchange" {
        return Ok(None);
    }
    Ok(Some(summarize(
        &json!({"sql":facts.sql,"connection_id":facts.connection_id,"query_sequence":facts.query_sequence,
        "server_status_before":facts.server_status_before,"response":{"server_status":facts.response},
        "target_host":facts.target_host,"target_port":facts.target_port,"database":facts.database,"username":facts.username,"command":facts.command}),
    )))
}

#[derive(Deserialize)]
struct SqlRecord {
    #[serde(default)]
    event_type: String,
    #[serde(default)]
    sql: Option<String>,
    #[serde(default)]
    connection_id: Value,
    #[serde(default)]
    query_sequence: Value,
    #[serde(default)]
    server_status_before: Value,
    #[serde(default, deserialize_with = "response_status")]
    response: Value,
    #[serde(default)]
    target_host: Value,
    #[serde(default)]
    target_port: Value,
    #[serde(default)]
    database: Value,
    #[serde(default)]
    username: Value,
    #[serde(default)]
    command: Value,
}

// Keep only wire-state metadata, without materializing any protocol's response body.
fn response_status<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Value, D::Error> {
    struct Status;
    impl<'de> serde::de::Visitor<'de> for Status {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a response envelope")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Value, M::Error> {
            let mut status = Value::Null;
            while let Some(key) = map.next_key::<String>()? {
                if key == "server_status" {
                    status = map.next_value()?;
                } else {
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
            Ok(status)
        }
        fn visit_seq<S: serde::de::SeqAccess<'de>>(
            self,
            mut seq: S,
        ) -> std::result::Result<Value, S::Error> {
            while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(Value::Null)
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
    }
    d.deserialize_any(Status)
}

pub fn endpoint(event: &Value) -> Option<traffic_protocol::evidence::index::IndexEndpoint> {
    let tag = event["event_type"].as_str()?;
    if !matches!(tag, "mysql_exchange" | "mysql_connection") {
        return None;
    }
    let command = event["command"].as_str().unwrap_or_default();
    if tag == "mysql_exchange"
        && (crate::is_no_response_command(command)
            || event.get("outcome").is_none_or(|value| value == "response")
                && (command == "COM_PING" && event["response"]["status"] == "ok"
                    || command == "COM_STMT_PREPARE"
                        && event["response"]["status"] == "stmt_prepare"))
    {
        return None;
    }
    let target = event["target_host"]
        .as_str()
        .zip(
            event["target_port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok()),
        )
        .map(|(host, port)| (host.to_owned(), port))
        .or_else(|| {
            let endpoint =
                traffic_protocol::connection::endpoint_from_addr(event["target_addr"].as_str()?)?;
            Some((endpoint.host, endpoint.port))
        })?;
    Some(traffic_protocol::evidence::index::IndexEndpoint {
        host: target.0.trim_end_matches('.').to_ascii_lowercase(),
        port: target.1,
        protocol: "mysql".into(),
    })
}
