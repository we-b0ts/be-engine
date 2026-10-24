//! Native assertion fields retain their contract while reusing response owners.
use anyhow::{Context, Result};

use super::super::response as r;
use super::*;

pub(super) fn project(output: &mut NativeRuntimeProjection, rule: &n::NativeRule) -> Result<()> {
    let api = rule
        .selector
        .api
        .as_deref()
        .context("native assertion API is absent")?;
    match &rule.effect {
        n::NativeEffect::ResponseJwt(effect) => {
            let jwt = project_jwt(effect, rule.proof.as_ref())?;
            jwt.validate()?;
            if jwt.header.is_some() {
                return Ok(());
            }
            output.response_aliases.insert(jwt.id(api), rule.id.clone());
            output
                .document
                .response_rules
                .json
                .entry(api.into())
                .or_default()
                .jwt
                .push(jwt);
        }
        n::NativeEffect::ResponseHeaderDate(effect) => {
            let (_, path) = api.split_once(' ').context("invalid native header API")?;
            let header = super::super::response_headers::ResponseHeaderDateRule {
                header: effect.header.clone(),
                parameter: effect.parameter.clone(),
                format: effect.format.clone(),
                timezone: effect.timezone.clone(),
                source_evidence: proof(rule.proof.as_ref()),
            };
            header.validate()?;
            output
                .response_aliases
                .insert(header.id(path), rule.id.clone());
            output
                .document
                .response_rules
                .headers
                .entry(path.into())
                .or_default()
                .push(header);
        }
        n::NativeEffect::ResponseBody(effect) => {
            // Codec selection itself is a strict body contract, including zero
            // relaxed fields. Preserve it in the typed domain projection.
            match effect.codec {
                n::BodyCodec::Json => {
                    output
                        .document
                        .response_rules
                        .json
                        .entry(api.into())
                        .or_default();
                }
                n::BodyCodec::Protobuf => {
                    output
                        .document
                        .response_rules
                        .protobuf
                        .entry(api.into())
                        .or_default();
                }
                n::BodyCodec::Hessian2 => {
                    output
                        .document
                        .response_rules
                        .hessian2
                        .entry(api.into())
                        .or_default();
                }
                n::BodyCodec::Docx => {
                    output
                        .document
                        .response_rules
                        .docx
                        .entry(api.into())
                        .or_default();
                }
            }
            for field in &effect.fields {
                body_field(output, rule, api, &field.contract, field.proof.as_ref())?;
            }
        }
        _ => anyhow::bail!("native effect is not a structured assertion"),
    }
    Ok(())
}

fn body_field(
    output: &mut NativeRuntimeProjection,
    rule: &n::NativeRule,
    api: &str,
    field: &n::BodyField,
    field_proof: Option<&crate::policy::Proof>,
) -> Result<()> {
    let source_evidence = proof(field_proof);
    match field {
        n::BodyField::Unordered {
            selector: n::BodySelector::Json { pointer },
        } => {
            output
                .document
                .response_rules
                .json
                .entry(api.into())
                .or_default()
                .unordered
                .push(r::JsonUnorderedResponseRule {
                    pointer: pointer.clone(),
                    source_evidence,
                });
        }
        n::BodyField::JoinedString {
            selector: n::BodySelector::Json { pointer },
            separator,
        } => {
            output
                .document
                .response_rules
                .json
                .entry(api.into())
                .or_default()
                .unordered_joined_string
                .push(r::JsonJoinedStringResponseRule {
                    pointer: pointer.clone(),
                    separator: separator.clone(),
                    source_evidence,
                });
        }
        n::BodyField::Unordered {
            selector:
                n::BodySelector::Protobuf {
                    field_path,
                    alias,
                    element_type,
                },
        } => {
            output
                .document
                .response_rules
                .protobuf
                .entry(api.into())
                .or_default()
                .unordered
                .push(r::ProtobufUnorderedPath {
                    field_path: r::ProtobufFieldPath(field_path.clone()),
                    display_path: alias.clone(),
                    element_type: protobuf_element(*element_type),
                    source_evidence,
                });
        }
        n::BodyField::JoinedString {
            selector:
                n::BodySelector::Protobuf {
                    field_path, alias, ..
                },
            separator,
        } => {
            output
                .document
                .response_rules
                .protobuf
                .entry(api.into())
                .or_default()
                .unordered_joined_string
                .push(r::ProtobufJoinedStringPath {
                    field_path: r::ProtobufFieldPath(field_path.clone()),
                    display_path: alias.clone(),
                    field_type: r::ProtobufJoinedStringFieldType::String,
                    separator: separator.clone(),
                    source_evidence,
                });
        }
        n::BodyField::Unordered {
            selector: n::BodySelector::Hessian2 { value_path, alias },
        } => {
            output
                .document
                .response_rules
                .hessian2
                .entry(api.into())
                .or_default()
                .unordered
                .push(r::Hessian2UnorderedPath {
                    value_path: r::Hessian2ValuePath(value_path.clone()),
                    display_path: alias.clone(),
                    source_evidence,
                });
        }
        n::BodyField::JoinedString {
            selector: n::BodySelector::Hessian2 { value_path, alias },
            separator,
        } => {
            output
                .document
                .response_rules
                .hessian2
                .entry(api.into())
                .or_default()
                .unordered_joined_string
                .push(r::Hessian2JoinedStringPath {
                    value_path: r::Hessian2ValuePath(value_path.clone()),
                    display_path: alias.clone(),
                    separator: separator.clone(),
                    source_evidence,
                });
        }
        n::BodyField::Timestamp {
            part,
            element,
            format,
        } => {
            // Historical fields were plan diagnostics. Native proof and witness
            // validation replace them; no payload examples are manufactured here.
            output
                .document
                .response_rules
                .docx
                .entry(api.into())
                .or_default()
                .timestamp
                .push(r::DocxTimestampRule {
                    part: part.clone(),
                    element: element.clone(),
                    format: dependency::response_format(*format)?,
                    source_evidence,
                    source_example: String::new(),
                    target_example: String::new(),
                });
        }
    }
    let _ = rule;
    Ok(())
}

fn algorithm(value: n::SignatureAlgorithm) -> r::ResponseJwtAlgorithm {
    match value {
        n::SignatureAlgorithm::HS256 => r::ResponseJwtAlgorithm::HS256,
        n::SignatureAlgorithm::HS384 => r::ResponseJwtAlgorithm::HS384,
        n::SignatureAlgorithm::HS512 => r::ResponseJwtAlgorithm::HS512,
        n::SignatureAlgorithm::RS256 => r::ResponseJwtAlgorithm::RS256,
    }
}

fn response_key(value: &n::ResponseSigningKey) -> Result<r::ResponseJwtKeySource> {
    Ok(match value {
        n::ResponseSigningKey::Startup {
            source: n::StartupKey::TargetEnv { name },
        } => r::ResponseJwtKeySource::TargetEnv { name: name.clone() },
        n::ResponseSigningKey::Startup {
            source: n::StartupKey::TargetFile { path, field },
        } => r::ResponseJwtKeySource::TargetFile {
            path: path.into(),
            field: field.clone(),
        },
        n::ResponseSigningKey::RecordedPublicKey {
            resource,
            sql,
            params,
            column,
            json_pointer,
            kid_pointer,
            algorithm_pointer,
            kid,
        } => r::ResponseJwtKeySource::RecordedMysql {
            host: resource.endpoint.host.clone(),
            port: resource.endpoint.port,
            database: resource
                .database
                .as_ref()
                .and_then(crate::policy::Database::name)
                .context("public-key database is absent")?
                .into(),
            sql: sql.clone(),
            params: params.iter().map(n::Literal::as_json).collect(),
            column: column.clone(),
            json_pointer: json_pointer.clone(),
            kid_pointer: kid_pointer.clone(),
            algorithm_pointer: algorithm_pointer.clone(),
            kid: kid.clone(),
        },
    })
}

pub(in crate::replay) fn dynamic_claim(
    value: &n::NonceClaim,
) -> crate::request_rules::JwtDynamicClaim {
    let (format, decoded_bytes) = match value.format {
        n::NonceFormat::UuidV4 => (crate::request_rules::JwtNonceFormat::UuidV4, None),
        n::NonceFormat::Base64url { decoded_bytes } => (
            crate::request_rules::JwtNonceFormat::Base64url,
            Some(decoded_bytes),
        ),
    };
    crate::request_rules::JwtDynamicClaim::Typed(crate::request_rules::JwtNonceClaim {
        pointer: value.pointer.clone(),
        format,
        decoded_bytes,
    })
}

fn protobuf_element(value: n::ProtobufElement) -> r::ProtobufRepeatedElementType {
    match value {
        n::ProtobufElement::String => r::ProtobufRepeatedElementType::String,
        n::ProtobufElement::Message => r::ProtobufRepeatedElementType::Message,
        n::ProtobufElement::Int32 => r::ProtobufRepeatedElementType::Int32,
        n::ProtobufElement::Int64 => r::ProtobufRepeatedElementType::Int64,
        n::ProtobufElement::Uint32 => r::ProtobufRepeatedElementType::Uint32,
        n::ProtobufElement::Uint64 => r::ProtobufRepeatedElementType::Uint64,
        n::ProtobufElement::Sint32 => r::ProtobufRepeatedElementType::Sint32,
        n::ProtobufElement::Sint64 => r::ProtobufRepeatedElementType::Sint64,
        n::ProtobufElement::Bool => r::ProtobufRepeatedElementType::Bool,
        n::ProtobufElement::Enum => r::ProtobufRepeatedElementType::Enum,
        n::ProtobufElement::Fixed32 => r::ProtobufRepeatedElementType::Fixed32,
        n::ProtobufElement::Sfixed32 => r::ProtobufRepeatedElementType::Sfixed32,
        n::ProtobufElement::Float => r::ProtobufRepeatedElementType::Float,
        n::ProtobufElement::Fixed64 => r::ProtobufRepeatedElementType::Fixed64,
        n::ProtobufElement::Sfixed64 => r::ProtobufRepeatedElementType::Sfixed64,
        n::ProtobufElement::Double => r::ProtobufRepeatedElementType::Double,
    }
}

pub(in crate::replay) fn project_jwt(
    effect: &n::ResponseJwtEffect,
    source_proof: Option<&crate::policy::Proof>,
) -> Result<r::ResponseJwtRule> {
    let jwt = r::ResponseJwtRule {
        pointer: effect.pointer.clone(),
        header: effect
            .location
            .as_ref()
            .map(|location| location.header.to_ascii_lowercase()),
        nonce_query_params: effect
            .nonces
            .iter()
            .filter_map(|nonce| {
                nonce
                    .contract
                    .echo_query_param
                    .as_ref()
                    .map(|name| (nonce.contract.pointer.clone(), name.clone()))
            })
            .collect(),
        algorithm: algorithm(effect.algorithm),
        signing_key_source: response_key(&effect.signing_key)?,
        dynamic_claims: effect
            .nonces
            .iter()
            .map(|nonce| {
                dynamic_claim(&n::NonceClaim {
                    pointer: nonce.contract.pointer.clone(),
                    format: nonce.contract.format.clone(),
                })
            })
            .collect(),
        url_query_param: effect.url_query_param.clone(),
        expires_at: effect.expires_at.clone(),
        expires_at_format: dependency::response_format(effect.expires_at_format)?,
        issued_at: effect.issued_at.clone(),
        ttl: effect.ttl.clone(),
        source_evidence: proof(source_proof),
    };
    jwt.validate()?;
    Ok(jwt)
}
