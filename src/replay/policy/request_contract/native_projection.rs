//! Native atomic request effects are projected directly into this owner's types.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};

use crate::policy::native as n;
use crate::policy::{TimeAnchor, TimeRelation, TimestampFormat};

use super::{config, key};

pub(in crate::replay::policy) fn sequence(
    rule: &n::NativeRule,
    effect: &n::RedisSequenceEffect,
) -> Result<config::RedisRequestSelector> {
    let resource = rule.selector.resource.as_ref();
    let selector = config::RedisRequestSelector {
        database: resource.and_then(|resource|resource.database.as_ref()).and_then(crate::policy::Database::index),
        key: super::super::native_projection::key(rule.selector.key.as_ref().context("sequence key is absent")?),
        key_contract: effect.key.as_ref().map(|value| key_contract(&value.contract)),
        commands: effect.commands.iter().map(|command| {
            let arguments = command.arguments.iter().map(|(index,argument)| {
                let location=format!("{}:{index}",command.operation);
                let value=match &argument.contract {
                    n::SequenceArgument::Time(value) => config::ArgumentRule::Time(time(&rule.id,&location,value)?),
                    n::SequenceArgument::Json {fields} => config::ArgumentRule::Json(config::JsonArgument {
                        json:fields.iter().map(|(pointer,field)| {
                            let location=format!("{location}:{pointer}");
                            let field=match &field.contract {
                                n::SequenceField::Time(value)=>config::JsonField::Time(time(&rule.id,&location,value)?),
                                n::SequenceField::Identity(value)=>config::JsonField::Identity(key::IdentityField {identity:reference(value)}),
                                n::SequenceField::Random {format, length, max_length}=>config::JsonField::Random(config::RandomField {
                                    random: config::RandomContract { format: format.clone(), length: *length, max_length: *max_length },
                                }),
                                n::SequenceField::Url {query}=>config::JsonField::Url(config::UrlField {
                                    url: query.iter().map(|(name, field)| Ok((name.clone(), match &field.contract {
                                        n::SequenceUrlField::Time(value)=>config::UrlQueryField::Time(time(&rule.id,&format!("{location}:{name}"),value)?),
                                        n::SequenceUrlField::UtcDateSegment(value)=>config::UrlQueryField::UtcDateSegment {utc_date_segment:value.clone()},
                                        n::SequenceUrlField::Random {format,length}=>config::UrlQueryField::Random(config::RandomField {
                                            random: config::RandomContract {format:format.clone(),length:Some(*length),max_length:None},
                                        }),
                                    }))).collect::<Result<_>>()?,
                                }),
                                n::SequenceField::Jwt {algorithm,signing_key,relative_to,nonces}=>{
                                    config::JsonField::Jwt(config::JwtField {jwt:config::JwtContract {
                                        signing_key_source:super::super::native_projection::startup_key(signing_key),
                                        algorithm:super::super::native_projection::hmac_algorithm(*algorithm)?,
                                        relative_to:relative_to.clone(),
                                        tolerance:"5s".into(),
                                        dynamic_claims:nonces.iter().map(|nonce|super::super::native_projection::dynamic_claim(&nonce.contract)).collect(),
                                    }})
                                }
                            };
                            Ok((pointer.clone(),field))
                        }).collect::<Result<BTreeMap<_,_>>>()?,
                    }),
                };
                Ok((*index,value))
            }).collect::<Result<BTreeMap<_,_>>>()?;
            Ok(config::RedisRequestCommand {
                command:command.operation.clone(),
                script:command.script.as_ref().map(|script|config::RedisScriptIdentity {
                    sha1:script.contract.sha1.clone(),sha256:script.contract.sha256.clone(),
                }),
                argument_values:arguments,
            })
        }).collect::<Result<Vec<_>>>()?,
    };
    selector.validate()?;
    Ok(selector)
}

pub(in crate::replay::policy) fn time(
    _rule_id: &str,
    _location: &str,
    value: &n::NativeTime,
) -> Result<config::TimeField> {
    ensure!(
        matches!(
            value.anchor,
            TimeAnchor::Observation | TimeAnchor::DependencyRequestStart
        ) && value.relation == TimeRelation::PreserveOffset,
        "atomic Redis sequence timestamps require preserve_offset and the corresponding dependency request start"
    );
    let format = match value.format {
        TimestampFormat::UnixSeconds => config::RequestTimestampFormat::UnixSeconds,
        TimestampFormat::UnixMilliseconds => config::RequestTimestampFormat::UnixMilliseconds,
        TimestampFormat::UnixMicroseconds => config::RequestTimestampFormat::UnixMicroseconds,
        TimestampFormat::Rfc3339 => config::RequestTimestampFormat::Rfc3339,
        TimestampFormat::Iso8601Naive => config::RequestTimestampFormat::Iso8601Naive,
        TimestampFormat::AmzDate => config::RequestTimestampFormat::AmzDate,
        TimestampFormat::SqlDatetime => config::RequestTimestampFormat::SqlDatetime,
        TimestampFormat::CalendarDate => {
            anyhow::bail!("calendar_date requires a value codec contract")
        }
    };
    let projected = config::TimeField {
        time: config::RelativeTime::PreserveRelative,
        format,
        anchor: value.anchor,
        utc_offset: value.utc_offset.clone(),
        clock_group: value.clock_group.clone(),
        tolerance: "5s".into(),
    };
    projected.validate()?;
    Ok(projected)
}

fn key_contract(value: &n::NativeKeyContract) -> key::KeyContract {
    match value {
        n::NativeKeyContract::TimeWindow {
            window_seconds,
            separator,
            segment_index,
        } => key::KeyContract::TimeWindow {
            window_seconds: *window_seconds,
            separator: *separator,
            segment_index: *segment_index,
        },
        n::NativeKeyContract::Capture { template, format } => key::KeyContract::Capture {
            template: template.clone(),
            format: match format {
                n::KeyIdentityFormat::Hex { bytes } => key::KeyFormat::Hex { bytes: *bytes },
                n::KeyIdentityFormat::Base64url { bytes } => {
                    key::KeyFormat::Base64url { bytes: *bytes }
                }
                n::KeyIdentityFormat::UuidV4 => key::KeyFormat::UuidV4,
            },
        },
        n::NativeKeyContract::Reference(value) => key::KeyContract::Reference {
            template: value.template.clone(),
            transform: transform(value.transform),
        },
    }
}

fn reference(value: &n::IdentityReference) -> key::IdentityReference {
    key::IdentityReference {
        template: value.template.clone(),
        transform: transform(value.transform),
    }
}

fn transform(value: n::IdentityTransform) -> key::Transform {
    match value {
        n::IdentityTransform::Identity => key::Transform::Identity,
        n::IdentityTransform::Sha256 => key::Transform::Sha256,
    }
}
