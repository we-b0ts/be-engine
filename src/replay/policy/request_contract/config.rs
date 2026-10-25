//! Explicit Redis/HTTP request timestamps, signed values and multipart contracts.
use crate::replay::redis::key_selector::RedisValueKeySelector;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RedisRequestSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<i64>,
    pub key: RedisValueKeySelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_contract: Option<super::key::KeyContract>,
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
    Identity(super::key::IdentityField),
    Random(RandomField),
    Url(UrlField),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UrlField {
    pub url: BTreeMap<String, UrlQueryField>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum UrlQueryField {
    Time(TimeField),
    Random(RandomField),
    UtcDateSegment {
        utc_date_segment: crate::policy::native::UtcDateSegment,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RandomField {
    pub random: RandomContract,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RandomContract {
    pub format: crate::policy::native::RandomEncoding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
}

impl RandomContract {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::value_contract::generated::validate_bounded_random(
            &self.format,
            self.length,
            self.max_length,
        )
    }

    pub(super) fn compare(
        &self,
        source: &serde_json::Value,
        target: &serde_json::Value,
    ) -> Result<()> {
        crate::value_contract::generated::compare_bounded_random(
            source,
            target,
            &self.format,
            self.length,
            self.max_length,
        )
        .map_err(|_| anyhow::anyhow!("random Redis JSON field has invalid type or encoding"))?;
        Ok(())
    }
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TimeField {
    pub time: RelativeTime,
    pub format: RequestTimestampFormat,
    #[serde(skip)]
    pub anchor: crate::policy::TimeAnchor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utc_offset: Option<String>,
    /// Fields from one source-proven clock read (or derived time window).
    /// Absent names retain the legacy single shared group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_group: Option<String>,
    #[serde(default = "default_tolerance", skip_serializing)]
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
pub(crate) enum RequestTimestampFormat {
    UnixSeconds,
    UnixMilliseconds,
    UnixMicroseconds,
    Rfc3339,
    Iso8601Naive,
    SqlDatetime,
    AmzDate,
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
    #[serde(default = "default_tolerance", skip_serializing)]
    pub tolerance: String,
    #[serde(default)]
    pub dynamic_claims: Vec<crate::request_rules::JwtDynamicClaim>,
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
    ensure!(seconds == 5.0, "request tolerance is fixed at 5s");
    Ok(seconds)
}

impl TimeField {
    pub(crate) fn validate(&self) -> Result<()> {
        tolerance(&self.tolerance)?;
        ensure!(
            self.anchor == crate::policy::TimeAnchor::DependencyRequestStart,
            "Redis request times require the corresponding dependency request start"
        );
        if let Some(group) = &self.clock_group {
            ensure!(
                !group.is_empty()
                    && group.len() <= 64
                    && group
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
                "clock_group requires 1..64 ASCII letters, digits, underscores or hyphens"
            );
        }
        if matches!(
            self.format,
            RequestTimestampFormat::Iso8601Naive | RequestTimestampFormat::SqlDatetime
        ) {
            super::time::offset(self)?;
        } else {
            ensure!(
                self.utc_offset.is_none(),
                "utc_offset is only valid for a naive timestamp"
            );
        }
        Ok(())
    }
}

impl RedisRequestSelector {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.database.is_none_or(|database| database >= 0)
                && !self.commands.is_empty()
                && self.commands.len() <= 16,
            "Redis request rules require a database and 1..16 commands"
        );
        self.key.validate()?;
        if let Some(key) = &self.key_contract {
            key.validate()?;
        }
        let mut commands = std::collections::BTreeSet::new();
        for command in &self.commands {
            command.validate_script()?;
            if command.command == "PUBLISH" {
                ensure!(
                    self.commands.len() == 1
                        && self.key_contract.is_none()
                        && matches!(self.key, RedisValueKeySelector::Exact { .. }),
                    "PUBLISH time contracts require one command and an exact channel"
                );
            }
            ensure!(
                commands.insert(&command.command),
                "duplicate Redis request command"
            );
            ensure!(
                (!command.argument_values.is_empty() || self.key_contract.is_some())
                    && command.argument_values.len() <= 32,
                "Redis request rules require 1..32 argument locations or an explicit key contract"
            );
            if let Some(key) = &self.key_contract {
                ensure!(
                    match key {
                        super::key::KeyContract::TimeWindow { .. } =>
                            matches!(command.command.as_str(), "INCRBY" | "EXPIRE"),
                        _ => matches!(
                            command.command.as_str(),
                            "SET" | "SUBSCRIBE" | "UNSUBSCRIBE"
                        ),
                    },
                    "key contract selects INCRBY/EXPIRE windows or SET/SUBSCRIBE/UNSUBSCRIBE identities"
                );
            }
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
                        time.validate()?;
                    }
                    ArgumentRule::Json(json) => {
                        ensure!(
                            command.command == "SET" && *index == 1
                                || command.command == "LSET" && *index == 2
                                || matches!(command.command.as_str(), "RPUSH" | "LPUSH")
                                    && (1..=128).contains(index)
                                || command.command == "PUBLISH" && *index == 1
                                || matches!(command.command.as_str(), "EVAL" | "EVALSHA")
                                    && (3..=128).contains(index),
                            "JSON request rules select SET/PUBLISH value index 1, LSET element index 2, LPUSH/RPUSH elements or bounded script ARGV"
                        );
                        ensure!(
                            !json.json.is_empty() && json.json.len() <= 32,
                            "JSON request rules require 1..32 fields"
                        );
                        for (pointer, field) in &json.json {
                            ensure!(
                                command.command != "PUBLISH"
                                    || matches!(field, JsonField::Time(_) | JsonField::Url(_)),
                                "PUBLISH request fields support time and URL contracts; UUID bindings retain their own rules"
                            );
                            super::super::response::validate_json_pointer(pointer)?;
                            ensure!(
                                !pointer.is_empty(),
                                "request fields require non-root pointers"
                            );
                            match field {
                                JsonField::Identity(reference) => reference.identity.validate()?,
                                JsonField::Random(field) => field.random.validate()?,
                                JsonField::Url(field) => {
                                    ensure!(
                                        (1..=16).contains(&field.url.len()),
                                        "URL requires 1..16 query fields"
                                    );
                                    for (name, query) in &field.url {
                                        crate::value_contract::url_query::validate_name(name)?;
                                        match query {
                                            UrlQueryField::UtcDateSegment {
                                                utc_date_segment: segment,
                                            } => {
                                                ensure!(
                                                    segment.index < 64
                                                        && segment.separator.is_ascii_punctuation()
                                                        && !matches!(
                                                            segment.separator,
                                                            '&' | '=' | '?' | '#'
                                                        )
                                                        && matches!(
                                                            field.url.get(&segment.relative_to),
                                                            Some(UrlQueryField::Time(_))
                                                        ),
                                                    "URL UTC date segment requires a bounded segment and a selected query time"
                                                );
                                            }
                                            UrlQueryField::Time(time) => {
                                                ensure!(
                                                    matches!(
                                                        time.format,
                                                        RequestTimestampFormat::AmzDate
                                                            | RequestTimestampFormat::Rfc3339
                                                            | RequestTimestampFormat::Iso8601Naive
                                                            | RequestTimestampFormat::SqlDatetime
                                                    ),
                                                    "URL query times require a textual timestamp format"
                                                );
                                                time.validate()?;
                                            }
                                            UrlQueryField::Random(random) => {
                                                ensure!(
                                                    random.random.max_length.is_none(),
                                                    "URL query random values require a fixed encoded length"
                                                );
                                                random.random.validate()?;
                                            }
                                        }
                                    }
                                }
                                JsonField::Time(time) => {
                                    time.validate()?;
                                }
                                JsonField::Jwt(field) => {
                                    ensure!(
                                        !pointer.split('/').any(|p| p == "*"),
                                        "JWT request fields require exact pointers"
                                    );
                                    ensure!(
                                        command.command == "SET",
                                        "signed JSON request fields currently select SET values"
                                    );
                                    crate::request_rules::keys::validate_source(
                                        &field.jwt.signing_key_source,
                                    )?;
                                    tolerance(&field.jwt.tolerance)?;
                                    ensure!(
                                        field.jwt.dynamic_claims.len() <= 16,
                                        "JWT supports at most sixteen typed nonces"
                                    );
                                    let mut claims = BTreeSet::new();
                                    for claim in &field.jwt.dynamic_claims {
                                        claim.validate()?;
                                        ensure!(
                                            claims.insert(claim.pointer()),
                                            "duplicate request JWT nonce claim"
                                        );
                                    }
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
