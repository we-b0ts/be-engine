//! Explicit Redis request locations and multipart transport comparison contracts.
use crate::replay::redis::key_selector::RedisValueKeySelector;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RedisRequestSelector {
    #[serde(default)]
    pub database: i64,
    pub key: RedisValueKeySelector,
    pub commands: Vec<RedisRequestCommand>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RedisRequestCommand {
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<RedisScriptIdentity>,
    #[serde(deserialize_with = "argument_values")]
    pub argument_values: BTreeMap<usize, ArgumentRule>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RedisScriptIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum ArgumentRule {
    Time(TimeField),
    Json(JsonArgument),
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JsonArgument {
    pub json: BTreeMap<String, JsonField>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum JsonField {
    Time(TimeField),
    Jwt(JwtField),
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TimeField {
    pub time: RelativeTime,
    pub format: UnixTimeFormat,
    #[serde(default = "default_tolerance")]
    pub tolerance: String,
}
fn default_tolerance() -> String {
    "5s".into()
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RelativeTime {
    PreserveRelative,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UnixTimeFormat {
    UnixSeconds,
    UnixMilliseconds,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JwtField {
    pub jwt: JwtContract,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JwtContract {
    pub signing_key_source: crate::request_rules::keys::SigningKeySource,
    pub algorithm: crate::request_rules::JwtAlgorithm,
    pub relative_to: String,
    #[serde(default = "default_tolerance")]
    pub tolerance: String,
    #[serde(default)]
    pub dynamic_claims: Vec<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MultipartRule {
    pub boundary: NormalizeBoundary,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NormalizeBoundary {
    Normalize,
}

pub(crate) fn tolerance(value: &str) -> Result<f64> {
    let seconds = value
        .strip_suffix('s')
        .ok_or_else(|| anyhow::anyhow!("request tolerance must be in seconds"))?
        .parse::<f64>()?;
    ensure!(
        seconds.is_finite() && seconds > 0.0 && seconds <= 5.0,
        "request tolerance must be greater than zero and at most 5s"
    );
    Ok(seconds)
}
impl RedisRequestSelector {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.database >= 0 && !self.commands.is_empty() && self.commands.len() <= 16,
            "Redis request rules require a database and 1..16 commands"
        );
        self.key.validate()?;
        let mut commands = std::collections::BTreeSet::new();
        for command in &self.commands {
            command.validate_script()?;
            ensure!(
                commands.insert(&command.command),
                "duplicate Redis request command"
            );
            ensure!(
                !command.argument_values.is_empty() && command.argument_values.len() <= 32,
                "Redis request rules require 1..32 argument locations"
            );
            for (index, field) in &command.argument_values {
                match field {
                    ArgumentRule::Time(time) => {
                        ensure!(
                            matches!(
                                (command.command.as_str(), index),
                                ("ZADD", 1) | ("ZREMRANGEBYSCORE", 2)
                            ) || matches!(command.command.as_str(), "EVAL" | "EVALSHA")
                                && (3..=128).contains(index),
                            "scalar time rules select ZADD/ZREMRANGEBYSCORE time slots or bounded script ARGV indices"
                        );
                        tolerance(&time.tolerance)?;
                    }
                    ArgumentRule::Json(json) => {
                        ensure!(
                            command.command == "SET" && *index == 1
                                || command.command == "RPUSH" && (1..=128).contains(index),
                            "JSON request rules select SET value index 1 or RPUSH element indices 1..128"
                        );
                        ensure!(
                            !json.json.is_empty() && json.json.len() <= 32,
                            "JSON request rules require 1..32 fields"
                        );
                        for (pointer, field) in &json.json {
                            super::super::response::validate_json_pointer(pointer)?;
                            ensure!(
                                !pointer.is_empty() && !pointer.split('/').any(|part| part == "*"),
                                "request fields require exact non-root pointers"
                            );
                            match field {
                                JsonField::Time(time) => {
                                    tolerance(&time.tolerance)?;
                                }
                                JsonField::Jwt(field) => {
                                    ensure!(
                                        command.command == "SET",
                                        "signed JSON request fields currently select SET values"
                                    );
                                    crate::request_rules::keys::validate_source(
                                        &field.jwt.signing_key_source,
                                    )?;
                                    tolerance(&field.jwt.tolerance)?;
                                    ensure!(
                                        matches!(
                                            json.json.get(&field.jwt.relative_to),
                                            Some(JsonField::Time(_))
                                        ),
                                        "JWT relative_to must select a time field in the same JSON argument"
                                    );
                                    ensure!(
                                        matches!(
                                            json.json.get(&field.jwt.relative_to),
                                            Some(JsonField::Time(TimeField {
                                                format: UnixTimeFormat::UnixSeconds,
                                                ..
                                            }))
                                        ),
                                        "JWT relative_to requires Unix seconds"
                                    );
                                    ensure!(
                                        field.jwt.dynamic_claims.is_empty()
                                            || field.jwt.dynamic_claims == ["/jti"],
                                        "JWT dynamic claims support only an explicit UUID v4 /jti"
                                    );
                                }
                            }
                            ensure!(
                                json.json.keys().all(|other| pointer == other
                                    || !super::super::response_locations_overlap(pointer, other)),
                                "request JSON fields overlap"
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn argument_values<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<usize, ArgumentRule>, D::Error> {
    #[derive(Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(untagged)]
    enum Index {
        Number(usize),
        Text(String),
    }
    let fields = BTreeMap::<Index, ArgumentRule>::deserialize(deserializer)?;
    let mut output = BTreeMap::new();
    for (index, field) in fields {
        let index = match index {
            Index::Number(index) => index,
            Index::Text(index) => index.parse().map_err(serde::de::Error::custom)?,
        };
        if output.insert(index, field).is_some() {
            return Err(serde::de::Error::custom("duplicate Redis argument index"));
        }
    }
    Ok(output)
}
