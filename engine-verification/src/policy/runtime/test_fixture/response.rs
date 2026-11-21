//! Mechanical conversion of synthetic assertion fixtures to the public AST.
use super::super::response as r;
use super::*;

#[allow(dead_code)]
pub(super) fn convert(
    rules: &r::ResponseRules,
    inventory: &Inventory,
) -> Result<Vec<p::PolicyRule>> {
    let mut output = vec![];
    for (api, rules) in &rules.json {
        let mut fields = BTreeMap::new();
        for rule in &rules.timestamp {
            fields.insert(
                rule.pointer.clone(),
                p::FieldContract::Time {
                    format: format(rule.format.context("fixture timestamp requires format")?),
                    relation: match rule.time.unwrap_or_default() {
                        r::ResponseTimestampMode::RequestWindow => p::TimeRelation::RequestWindow,
                        r::ResponseTimestampMode::PreserveRelative => {
                            p::TimeRelation::PreserveOffset
                        }
                    },
                    anchor: p::TimeAnchor::DependencyRequestStart,
                    utc_offset: None,
                    clock_group: None,
                    clock_scope: Default::default(),
                },
            );
        }
        for rule in &rules.duration {
            fields.insert(
                rule.pointer.clone(),
                p::FieldContract::Duration {
                    unit: match rule.unit.context("fixture duration requires unit")? {
                        r::ResponseDurationUnit::Seconds => p::DurationUnit::Seconds,
                        r::ResponseDurationUnit::Milliseconds => p::DurationUnit::Milliseconds,
                        r::ResponseDurationUnit::Minutes => p::DurationUnit::Minutes,
                        r::ResponseDurationUnit::Hours => p::DurationUnit::Hours,
                    },
                    anchor: p::TimeAnchor::DependencyRequestStart,
                },
            );
        }
        for rule in &rules.unordered {
            fields.insert(rule.pointer.clone(), p::FieldContract::Unordered);
        }
        if !fields.is_empty() {
            output.push(
                value(
                    &id("response-values", api),
                    p::Surface::ApiResponse,
                    p::MatchSpec {
                        api: Some(api.clone()),
                        ..Default::default()
                    },
                    p::Slot::Body,
                    p::Codec::Json,
                    fields,
                    value_semantics(
                        "Synthetic response fields explicitly selected by this fixture",
                        None,
                        None,
                    ),
                )
                .into(),
            );
        }
        let mut generated = BTreeMap::new();
        for rule in &rules.uuid {
            generated.insert(
                rule.pointer.clone(),
                proven(n::GeneratedResponse::Uuid, &rule.source_evidence),
            );
        }
        for rule in &rules.random {
            generated.insert(
                rule.pointer.clone(),
                proven(
                    n::GeneratedResponse::Random {
                        format: n::RandomEncoding::String,
                        length: None,
                    },
                    &rule.source_evidence,
                ),
            );
        }
        if !generated.is_empty() {
            output.push(
                native(
                    &id("response-generated", api),
                    n::NativeMatch {
                        api: Some(api.clone()),
                        ..Default::default()
                    },
                    n::NativeEffect::ResponseGenerated(n::GeneratedEffect { fields: generated }),
                    "Synthetic generated response values",
                    None,
                )
                .into(),
            );
        }
        for rule in &rules.jwt {
            let signing_key = match &rule.signing_key_source {
                r::ResponseJwtKeySource::TargetEnv { name } => n::ResponseSigningKey::Startup {
                    source: n::StartupKey::TargetEnv { name: name.clone() },
                },
                r::ResponseJwtKeySource::TargetFile { path, field } => {
                    n::ResponseSigningKey::Startup {
                        source: n::StartupKey::TargetFile {
                            path: path.to_string_lossy().into(),
                            field: field.clone(),
                        },
                    }
                }
                r::ResponseJwtKeySource::RecordedMysql {
                    host,
                    port,
                    database,
                    sql,
                    params,
                    column,
                    json_pointer,
                    kid_pointer,
                    algorithm_pointer,
                    kid,
                } => n::ResponseSigningKey::RecordedPublicKey {
                    resource: Box::new(p::Resource {
                        protocol: p::Protocol::Mysql,
                        endpoint: p::Endpoint {
                            host: host.clone(),
                            port: *port,
                        },
                        database: Some(p::Database::Name(database.clone())),
                        username: None,
                    }),
                    sql: sql.clone(),
                    params: params
                        .iter()
                        .cloned()
                        .map(serde_json::from_value)
                        .collect::<std::result::Result<_, _>>()?,
                    column: column.clone(),
                    json_pointer: json_pointer.clone(),
                    kid_pointer: kid_pointer.clone(),
                    algorithm_pointer: algorithm_pointer.clone(),
                    kid: kid.clone(),
                },
            };
            let algorithm = match rule.algorithm {
                r::ResponseJwtAlgorithm::HS256 => n::SignatureAlgorithm::HS256,
                r::ResponseJwtAlgorithm::HS384 => n::SignatureAlgorithm::HS384,
                r::ResponseJwtAlgorithm::HS512 => n::SignatureAlgorithm::HS512,
                r::ResponseJwtAlgorithm::RS256 => n::SignatureAlgorithm::RS256,
            };
            output.push(
                native(
                    &id("response-jwt", &format!("{api}:{}", rule.pointer)),
                    n::NativeMatch {
                        api: Some(api.clone()),
                        ..Default::default()
                    },
                    n::NativeEffect::ResponseJwt(n::ResponseJwtEffect {
                        pointer: rule.pointer.clone(),
                        location: rule.header.as_ref().map(|header| n::ResponseJwtLocation {
                            header: header.clone(),
                        }),
                        algorithm,
                        signing_key,
                        nonces: rule
                            .dynamic_claims
                            .iter()
                            .map(|claim| {
                                let mut value: n::ResponseNonceClaim = nonce(claim)?.into();
                                value.echo_query_param =
                                    rule.nonce_query_params.get(&value.pointer).cloned();
                                Ok(proven(value, &rule.source_evidence))
                            })
                            .collect::<Result<_>>()?,
                        url_query_param: rule.url_query_param.clone(),
                        expires_at: rule.expires_at.clone(),
                        expires_at_format: format(rule.expires_at_format),
                        issued_at: rule.issued_at.clone(),
                        ttl: rule.ttl.clone(),
                    }),
                    &rule.source_evidence,
                    None,
                )
                .into(),
            );
        }
        if !rules.unordered_joined_string.is_empty() {
            let fields = rules
                .unordered_joined_string
                .iter()
                .map(|field| {
                    proven(
                        n::BodyField::JoinedString {
                            selector: n::BodySelector::Json {
                                pointer: field.pointer.clone(),
                            },
                            separator: field.separator.clone(),
                        },
                        &field.source_evidence,
                    )
                })
                .collect();
            output.push(body(api, n::BodyCodec::Json, fields));
        }
    }
    for (path, rules) in &rules.headers {
        for rule in rules {
            let api = inventory.api(path);
            output.push(
                native(
                    &id(
                        "response-header",
                        &format!("{api}:{}:{:?}", rule.header, rule.parameter),
                    ),
                    n::NativeMatch {
                        api: Some(api),
                        ..Default::default()
                    },
                    n::NativeEffect::ResponseHeaderDate(n::HeaderDateEffect {
                        header: rule.header.clone(),
                        parameter: rule.parameter.clone(),
                        format: rule.format.clone(),
                        timezone: rule.timezone.clone(),
                    }),
                    &rule.source_evidence,
                    None,
                )
                .into(),
            );
        }
    }
    for (api, rules) in &rules.protobuf {
        let mut fields = rules
            .unordered
            .iter()
            .map(|field| {
                proven(
                    n::BodyField::Unordered {
                        selector: n::BodySelector::Protobuf {
                            field_path: field.field_path.0.clone(),
                            alias: alias(&field.display_path),
                            element_type: protobuf(field.element_type),
                        },
                    },
                    &field.source_evidence,
                )
            })
            .collect::<Vec<_>>();
        fields.extend(rules.unordered_joined_string.iter().map(|field| {
            proven(
                n::BodyField::JoinedString {
                    selector: n::BodySelector::Protobuf {
                        field_path: field.field_path.0.clone(),
                        alias: alias(&field.display_path),
                        element_type: n::ProtobufElement::String,
                    },
                    separator: field.separator.clone(),
                },
                &field.source_evidence,
            )
        }));
        output.push(body(api, n::BodyCodec::Protobuf, fields));
    }
    for (api, rules) in &rules.hessian2 {
        let mut fields = rules
            .unordered
            .iter()
            .map(|field| {
                proven(
                    n::BodyField::Unordered {
                        selector: n::BodySelector::Hessian2 {
                            value_path: field.value_path.0.clone(),
                            alias: field.display_path.clone(),
                        },
                    },
                    &field.source_evidence,
                )
            })
            .collect::<Vec<_>>();
        fields.extend(rules.unordered_joined_string.iter().map(|field| {
            proven(
                n::BodyField::JoinedString {
                    selector: n::BodySelector::Hessian2 {
                        value_path: field.value_path.0.clone(),
                        alias: field.display_path.clone(),
                    },
                    separator: field.separator.clone(),
                },
                &field.source_evidence,
            )
        }));
        output.push(body(api, n::BodyCodec::Hessian2, fields));
    }
    for (api, rules) in &rules.docx {
        let fields = rules
            .timestamp
            .iter()
            .map(|field| {
                proven(
                    n::BodyField::Timestamp {
                        part: field.part.clone(),
                        element: field.element.clone(),
                        format: format(field.format),
                    },
                    &field.source_evidence,
                )
            })
            .collect();
        output.push(body(api, n::BodyCodec::Docx, fields));
    }
    Ok(output)
}
#[allow(dead_code)]
fn body(api: &str, codec: n::BodyCodec, fields: Vec<n::Proven<n::BodyField>>) -> p::PolicyRule {
    native(
        &id("response-body", api),
        n::NativeMatch {
            api: Some(api.into()),
            ..Default::default()
        },
        n::NativeEffect::ResponseBody(n::BodyEffect { codec, fields }),
        "Synthetic structured response comparison",
        None,
    )
    .into()
}
#[allow(dead_code)]
fn alias(value: &str) -> String {
    if value.starts_with('/') {
        value.into()
    } else {
        format!("/{}", value.replace('.', "/"))
    }
}
#[allow(dead_code)]
pub(super) fn format(value: r::ResponseTimestampFormat) -> p::TimestampFormat {
    match value {
        r::ResponseTimestampFormat::UnixSeconds => p::TimestampFormat::UnixSeconds,
        r::ResponseTimestampFormat::UnixMilliseconds => p::TimestampFormat::UnixMilliseconds,
        r::ResponseTimestampFormat::Rfc3339 => p::TimestampFormat::Rfc3339,
        r::ResponseTimestampFormat::AmzDate => p::TimestampFormat::AmzDate,
    }
}
#[allow(dead_code)]
pub(super) fn nonce(value: &crate::request_rules::JwtDynamicClaim) -> Result<n::NonceClaim> {
    use crate::request_rules::{JwtDynamicClaim as D, JwtNonceFormat as F};
    value.validate()?;
    Ok(match value {
        D::Legacy(pointer) => n::NonceClaim {
            pointer: pointer.clone(),
            format: n::NonceFormat::UuidV4,
        },
        D::Typed(claim) => n::NonceClaim {
            pointer: claim.pointer.clone(),
            format: match claim.format {
                F::UuidV4 => n::NonceFormat::UuidV4,
                F::Base64url => n::NonceFormat::Base64url {
                    decoded_bytes: claim.decoded_bytes.expect("typed fixture nonce size"),
                },
            },
        },
    })
}
#[allow(dead_code)]
pub(super) fn protobuf(value: r::ProtobufRepeatedElementType) -> n::ProtobufElement {
    use r::ProtobufRepeatedElementType as P;
    match value {
        P::Message => n::ProtobufElement::Message,
        P::String => n::ProtobufElement::String,
        P::Int32 => n::ProtobufElement::Int32,
        P::Int64 => n::ProtobufElement::Int64,
        P::Uint32 => n::ProtobufElement::Uint32,
        P::Uint64 => n::ProtobufElement::Uint64,
        P::Sint32 => n::ProtobufElement::Sint32,
        P::Sint64 => n::ProtobufElement::Sint64,
        P::Bool => n::ProtobufElement::Bool,
        P::Enum => n::ProtobufElement::Enum,
        P::Fixed32 => n::ProtobufElement::Fixed32,
        P::Sfixed32 => n::ProtobufElement::Sfixed32,
        P::Float => n::ProtobufElement::Float,
        P::Fixed64 => n::ProtobufElement::Fixed64,
        P::Sfixed64 => n::ProtobufElement::Sfixed64,
        P::Double => n::ProtobufElement::Double,
    }
}
