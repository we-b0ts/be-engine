//! Protocol selector adaptation preserves native effect state boundaries.
use anyhow::{Context, Result, ensure};

use super::super::{config as c, redis_value as r};
use super::*;
use crate::policy::{TimeAnchor, TimeRelation, TimestampFormat};

pub(super) fn project(rule: &n::NativeRule) -> Result<ReplayDependencyRule> {
    let mut projected = dependency_rule(rule)?;
    let selector = &rule.selector;
    let resource = selector
        .resource
        .as_ref()
        .context("dependency resource is absent")?;
    match &rule.effect {
        n::NativeEffect::RedisSequence(effect) => {
            projected.redis = Some(r::RedisSelector::Requests(
                super::super::request_contract::native_projection::sequence(rule, effect)?,
            ));
            projected.source_evidence = proof(&rule.proof);
        }
        n::NativeEffect::RedisLock => {
            projected.redis = Some(r::RedisSelector::Lock(r::RedisLockConfig {
                lock: r::RedisLockField {
                    key: key(selector.key.as_ref().context("lock key is absent")?),
                    source_evidence: proof(&rule.proof),
                },
            }))
        }
        n::NativeEffect::RedisPublishIdentity(effect) => {
            projected.redis = Some(r::RedisSelector::Publish(r::RedisPublishConfig {
                publish: r::RedisPublishField {
                    channel: selector
                        .key
                        .as_ref()
                        .and_then(n::NativeKeySelector::exact)
                        .context("publisher channel is absent")?
                        .into(),
                    uuid_index: effect.uuid_index,
                    uuid_field: effect.uuid_field.clone(),
                    source_evidence: proof(&rule.proof),
                },
            }))
        }
        n::NativeEffect::HttpRequest(effect) => {
            let mut headers = BTreeMap::new();
            for (name, time) in &effect.headers {
                ensure!(
                    time.contract.anchor == TimeAnchor::DependencyRequestStart
                        && time.contract.relation == TimeRelation::RequestWindow
                        && time.contract.clock_group.is_none(),
                    "HTTP header timestamps require the independent dependency request window"
                );
                headers.insert(
                    name.clone(),
                    super::super::http_headers::HttpHeaderRule::Timestamp {
                        format: response_format(time.contract.format)?,
                        source_evidence: proof(&time.proof),
                    },
                );
            }
            projected.http = Some(c::HttpSelector {
                multipart: effect.multipart_boundary.then_some(
                    super::super::request_contract::config::MultipartRule {
                        boundary:
                            super::super::request_contract::config::NormalizeBoundary::Normalize,
                    },
                ),
                headers,
                json: super::super::http_json::HttpJsonRules::default(),
                method: selector
                    .operation
                    .clone()
                    .context("HTTP method is absent")?,
                path: selector.path.clone().context("HTTP path is absent")?,
                query: effect
                    .query
                    .iter()
                    .map(|(name, value)| {
                        Ok((
                            name.clone(),
                            match &value.contract {
                                n::GeneratedValue::Time(time) => {
                                    ensure!(
                                        time.anchor == TimeAnchor::ApiRequestStart,
                                        "HTTP query times require case.request_start"
                                    );
                                    c::DynamicValueRule {
                                        bind: None,
                                        reference: None,
                                        validate: None,
                                        time: Some(sql_time(time)?),
                                    }
                                }
                                value => generated(value)?,
                            },
                        ))
                    })
                    .collect::<Result<_>>()?,
            });
        }
        n::NativeEffect::MysqlValues(effect) => {
            let sql_values = effect
                .values
                .iter()
                .map(|(index, value)| {
                    let value = match &value.contract {
                        n::SqlValueContract::Time(time) => {
                            c::MysqlTimeValueRule::Scalar(mysql_time(time, &value.proof)?)
                        }
                        n::SqlValueContract::Json { fields } => c::MysqlTimeValueRule::Json(
                            fields
                                .iter()
                                .map(|(pointer, value)| {
                                    Ok((
                                        pointer.clone(),
                                        mysql_time(&value.contract, &value.proof)?,
                                    ))
                                })
                                .collect::<Result<_>>()?,
                        ),
                    };
                    Ok((*index, value))
                })
                .collect::<Result<_>>()?;
            let response_time_shift = effect
                .response_time
                .iter()
                .map(|(name, value)| {
                    ensure!(
                        value.contract.time.anchor == TimeAnchor::ApiRequestStart
                            && value.contract.time.relation == TimeRelation::PreserveOffset
                            && value.contract.time.format == TimestampFormat::SqlDatetime
                            && value.contract.time.utc_offset.is_some()
                            && value.contract.time.clock_group.is_none(),
                        "MySQL delivery time preserves case-relative offsets"
                    );
                    Ok((
                        name.clone(),
                        c::mysql_response::MysqlResponseTimeField {
                            time: c::TimeReference::PreserveRelative,
                            format: c::mysql_response::MysqlResponseTimeFormat::MysqlDatetime,
                            preserve_values: value.contract.preserve_values.clone(),
                        },
                    ))
                })
                .collect::<Result<_>>()?;
            projected.mysql = Some(c::MysqlSelector {
                command: selector
                    .operation
                    .clone()
                    .unwrap_or_else(|| "COM_QUERY".into()),
                sql: selector
                    .sql
                    .clone()
                    .context("MySQL SQL selector is absent")?,
                tables: selector.tables.clone(),
                table_patterns: selector.table_patterns.clone(),
                table_series: selector.table_series.clone(),
                database: resource
                    .database
                    .as_ref()
                    .and_then(crate::policy::Database::name)
                    .map(str::to_owned),
                username: resource.username.clone(),
                params: effect
                    .params
                    .iter()
                    .map(|(index, value)| Ok((*index, generated(&value.contract)?)))
                    .collect::<Result<_>>()?,
                sql_values,
                response_time_shift,
            });
            if !effect.response_time.is_empty() {
                projected.source_evidence = proof(&rule.proof);
            }
        }
        n::NativeEffect::FiniteSharing(effect) => {
            projected.replay_scope = ReplayScope::RecordingRun;
            projected.source_evidence = proof(&rule.proof);
            match effect {
                n::FiniteSharingEffect::Http => {
                    projected.http = Some(c::HttpSelector {
                        multipart: None,
                        headers: BTreeMap::new(),
                        json: super::super::http_json::HttpJsonRules::default(),
                        method: selector
                            .operation
                            .clone()
                            .context("shared HTTP method is absent")?,
                        path: selector
                            .path
                            .clone()
                            .context("shared HTTP path is absent")?,
                        query: BTreeMap::new(),
                    })
                }
                n::FiniteSharingEffect::Redis {
                    hash_field,
                    response_time,
                } => {
                    let response_json=response_time.iter().map(|(pointer,time)| {
                        ensure!(time.contract.anchor==TimeAnchor::DependencyDelivery && time.contract.relation==TimeRelation::PreserveOffset && time.contract.clock_group.is_none(),"shared Redis delivery uses a completion/delivery offset");
                        let format=match time.contract.format {
                            TimestampFormat::UnixSeconds=>crate::replay::redis::time_shift::RedisTimestampFormat::UnixSeconds,
                            TimestampFormat::UnixMilliseconds=>crate::replay::redis::time_shift::RedisTimestampFormat::UnixMilliseconds,
                            TimestampFormat::Rfc3339=>crate::replay::redis::time_shift::RedisTimestampFormat::Rfc3339,
                            _=>anyhow::bail!("shared Redis delivery timestamp format is unsupported"),
                        };
                        Ok((pointer.clone(),crate::replay::redis::time_shift::RelativeTimeField {time:crate::replay::redis::time_shift::RelativeTime::PreserveRelative,format}))
                    }).collect::<Result<_>>()?;
                    projected.redis = Some(r::RedisSelector::TimeShift(
                        crate::replay::redis::time_shift::RedisTimeShiftRead {
                            command: selector
                                .operation
                                .clone()
                                .context("shared Redis command is absent")?,
                            database: resource
                                .database
                                .as_ref()
                                .and_then(crate::policy::Database::index)
                                .context("shared Redis database is absent")?,
                            key: key(selector
                                .key
                                .as_ref()
                                .context("shared Redis key is absent")?),
                            hash_field: hash_field.as_ref().map(|field| {
                                crate::replay::RedisValueKeySelector::Exact {
                                    value: field.clone(),
                                }
                            }),
                            response_json,
                        },
                    ));
                }
            }
        }
        _ => anyhow::bail!("native effect is not a dependency-runtime effect"),
    }
    Ok(projected)
}

pub(in crate::replay::policy) fn generated(
    value: &n::GeneratedValue,
) -> Result<c::DynamicValueRule> {
    let mut result = c::DynamicValueRule {
        bind: None,
        reference: None,
        validate: None,
        time: None,
    };
    match value {
        n::GeneratedValue::Bind { binding } => result.bind = Some(binding.clone()),
        n::GeneratedValue::Uuid { binding } => {
            result.validate = Some(c::ValueValidator::Uuid);
            result.bind = binding.clone();
        }
        n::GeneratedValue::UuidV4 { binding } => {
            result.validate = Some(c::ValueValidator::UuidV4);
            result.bind = binding.clone();
        }
        n::GeneratedValue::NonEmpty { binding } => {
            result.bind = binding.clone();
            result.validate = Some(c::ValueValidator::NonEmpty);
        }
        n::GeneratedValue::Reference { binding } => result.reference = Some(binding.clone()),
        n::GeneratedValue::Time(_) => anyhow::bail!(
            "typed time contracts use MySQL values or value codecs, not params/query generated-value bindings"
        ),
    }
    Ok(result)
}

fn mysql_time(
    value: &n::NativeTime,
    source: &crate::policy::Proof,
) -> Result<c::MysqlTimeFieldRule> {
    ensure!(
        value.anchor != TimeAnchor::DependencyDelivery,
        "SQL request times cannot use a future response-delivery clock"
    );
    Ok(c::MysqlTimeFieldRule {
        source_evidence: proof(source),
        time: sql_time(value)?,
        anchor: value.anchor,
    })
}

fn sql_time(value: &n::NativeTime) -> Result<c::TimeRule> {
    ensure!(
        value.relation == TimeRelation::PreserveOffset,
        "SQL inventory projection requires preserve_offset"
    );
    let format = match value.format {
        TimestampFormat::UnixSeconds
        | TimestampFormat::UnixMilliseconds
        | TimestampFormat::UnixMicroseconds => None,
        TimestampFormat::Rfc3339 => Some("%+".into()),
        TimestampFormat::Iso8601Naive => Some("%Y-%m-%dT%H:%M:%S%.f".into()),
        TimestampFormat::SqlDatetime => Some("%Y-%m-%d %H:%M:%S%.f".into()),
        TimestampFormat::AmzDate => Some("%Y%m%dT%H%M%SZ".into()),
    };
    Ok(c::TimeRule {
        relative_to: c::TimeReference::PreserveRelative,
        offset: "0s".into(),
        tolerance: "5s".into(),
        format,
        timezone: value.utc_offset.clone(),
    })
}

pub(super) fn response_format(
    value: TimestampFormat,
) -> Result<super::super::response::ResponseTimestampFormat> {
    Ok(match value {
        TimestampFormat::UnixSeconds => {
            super::super::response::ResponseTimestampFormat::UnixSeconds
        }
        TimestampFormat::UnixMilliseconds => {
            super::super::response::ResponseTimestampFormat::UnixMilliseconds
        }
        TimestampFormat::Rfc3339 => super::super::response::ResponseTimestampFormat::Rfc3339,
        TimestampFormat::AmzDate => super::super::response::ResponseTimestampFormat::AmzDate,
        _ => anyhow::bail!("timestamp format is unsupported by this response domain"),
    })
}
