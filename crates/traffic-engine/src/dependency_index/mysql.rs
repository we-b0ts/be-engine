//! Optional SQL locations reuse the ordinary index and skip response payloads.
use super::{build::digest, model::*};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

/// SQL-free selector and wire facts shared by Recorder and legacy index repair.
pub(super) fn record(location: RecordLocation, value: &Value) -> Option<IndexedMysqlRecord> {
    if value["event_type"] != "mysql_exchange" {
        return None;
    }
    let sql = value["sql"].as_str().unwrap_or_default();
    let tokens = crate::mysql::sql::tokens(sql);
    let integer_hashes: Option<Vec<_>> = tokens.as_ref().map(|tokens| {
        tokens
            .iter()
            .filter_map(|token| match token {
                crate::mysql::sql::Token::Number(number) => Some(digest(number.as_bytes())),
                _ => None,
            })
            .collect()
    });
    Some(IndexedMysqlRecord {
        location,
        summary: json!({"target_host":value["target_host"],"target_port":value["target_port"],
            "database":value["database"],"username":value["username"],"command":value["command"],
            "sql_token_count":tokens.map(|tokens| tokens.len()),"integer_hashes":integer_hashes,
            "connection_id":value["connection_id"],"query_sequence":value["query_sequence"],
            "server_status_before":value["server_status_before"],"server_status_after":value["response"]["server_status"],
            "sql_summary":{"fingerprint":crate::config::process_owned_dependencies::mysql::evidence::fingerprint(sql)}}),
    })
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

pub(super) fn extend(path: &Path, mut index: FileIndex) -> Result<FileIndex> {
    index.mysql = Some(Vec::new());
    if !index.endpoints.iter().any(|e| e.protocol == "mysql") {
        return Ok(index);
    }
    let mut input = BufReader::new(File::open(path)?);
    let mut raw = Vec::new();
    let mut offset = 0;
    let mut line = 0;
    while input.read_until(b'\n', &mut raw)? != 0 {
        line += 1;
        if !raw.iter().all(u8::is_ascii_whitespace) {
            // Unknown fields use serde's IgnoredAny: large HTTP bodies and SQL
            // result rows are validated without allocating their contents.
            let facts: SqlRecord = serde_json::from_slice(&raw).with_context(|| {
                format!("invalid SQL index evidence {} line {line}", path.display())
            })?;
            if facts.event_type == "mysql_exchange" {
                // Non-SQL controls can carry the status continuity between two
                // statements. Keep them in legacy repairs as Recorder does.
                let sql = facts.sql.unwrap_or_default();
                let tokens = crate::mysql::sql::tokens(&sql);
                let integer_hashes: Option<Vec<_>> = tokens.as_ref().map(|ts| {
                    ts.iter()
                        .filter_map(|t| match t {
                            crate::mysql::sql::Token::Number(n) => Some(digest(n.as_bytes())),
                            _ => None,
                        })
                        .collect()
                });
                index.mysql.as_mut().expect("optional SQL index").push(IndexedMysqlRecord {
                    location: RecordLocation {line, offset, length: raw.len() as u64, sha256: digest(&raw)},
                    summary: json!({"target_host":facts.target_host,"target_port":facts.target_port,
                        "database":facts.database,"username":facts.username,"command":facts.command,
                        "sql_token_count":tokens.map(|t|t.len()), "integer_hashes":integer_hashes,
                        "connection_id":facts.connection_id,"query_sequence":facts.query_sequence,
                        "server_status_before":facts.server_status_before,"server_status_after":facts.response,
                        "sql_summary":{"fingerprint":crate::config::process_owned_dependencies::mysql::evidence::fingerprint(&sql)}}),
                });
            }
        }
        offset += raw.len() as u64;
        raw.clear();
    }
    ensure!(
        offset == index.stamp.size && FileStamp::read(path)? == index.stamp,
        "dependency file changed while extending SQL index"
    );
    Ok(index)
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
