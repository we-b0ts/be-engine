//! RESP request locations and encoding for framework-owned value rules.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::{Value, json};
use traffic_protocol::message::{
    MessageEncoder, ProjectedMessage, ProjectedValue, ProtocolMessage,
};

mod response;
pub use response::ResponseMessage;

#[derive(Clone)]
pub struct RequestMessage {
    pub command: String,
    pub args: Vec<Bytes>,
    pub resp_version: u8,
    pub database: i64,
    pub username: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestLocation {
    Request,
    Argument { index: usize },
    Key,
    HashField,
    Value,
}

impl ProtocolMessage for RequestMessage {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: json!({"command":self.command.to_ascii_uppercase(), "arguments":self.args.len(),
                "resp_version":self.resp_version, "database":self.database, "username":self.username}),
            values: self
                .args
                .iter()
                .enumerate()
                .map(|(index, value)| (location(index), ProjectedValue::bytes(value.clone())))
                .collect(),
        })
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        let selector: RequestLocation = serde_json::from_value(selector.clone())?;
        let command = self.command.to_ascii_uppercase();
        let indices = match selector {
            RequestLocation::Request => (0..self.args.len()).collect(),
            RequestLocation::Argument { index } => {
                ensure!(
                    index < self.args.len(),
                    "Redis argument selector is out of range"
                );
                vec![index]
            }
            RequestLocation::Key => crate::key_slots::key_indices(&command, &self.arguments())?,
            RequestLocation::HashField => match command.as_str() {
                "HSET" | "HMSET" => {
                    ensure!(
                        self.args.len() >= 3 && self.args.len() % 2 == 1,
                        "Redis hash field/value pairs are incomplete"
                    );
                    (1..self.args.len()).step_by(2).collect()
                }
                "HGET" | "HDEL" | "HMGET" | "HEXISTS" => {
                    ensure!(self.args.len() >= 2, "Redis hash fields are absent");
                    (1..self.args.len()).collect()
                }
                _ => Vec::new(),
            },
            RequestLocation::Value => {
                crate::value_rules::request_values(&command, &self.arguments())?
                    .into_iter()
                    .filter_map(|field| field.argument)
                    .collect()
            }
        };
        Ok(indices.into_iter().map(location).collect())
    }

    fn evidence(&self, query: &Value) -> Result<Value> {
        let projected = self.project()?;
        let arguments = self
            .locate(query)?
            .into_iter()
            .map(|location| {
                let capture = traffic_model::capture::capture_body(
                    &projected.values[&location].bytes,
                    usize::MAX,
                );
                json!({"location":location, "capture":capture})
            })
            .collect::<Vec<_>>();
        Ok(json!({"command":self.command, "database":self.database, "arguments":arguments}))
    }
}

impl MessageEncoder for RequestMessage {
    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        ensure!(
            values.len() == self.args.len(),
            "Redis encoding changes argument cardinality"
        );
        let command = self.command.as_bytes();
        let mut parts = vec![command];
        for index in 0..self.args.len() {
            parts.push(
                values
                    .get(&location(index))
                    .context("Redis encoding has no argument value")?
                    .as_ref(),
            );
        }
        Ok(crate::encode_array(&parts).into())
    }
}

impl RequestMessage {
    fn arguments(&self) -> Vec<Vec<u8>> {
        self.args.iter().map(|value| value.to_vec()).collect()
    }
}

fn location(index: usize) -> String {
    format!("/args/{index}")
}
