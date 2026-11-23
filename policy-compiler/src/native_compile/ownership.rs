//! Native field claims join value claims before either runtime is installed.
use serde::Serialize;
use std::cell::Cell;

use crate::{SourceCondition, native::*};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NativeFieldClaim {
    pub rule_id: String,
    pub surface: ClaimSurface,
    pub selector: NativeMatch,
    pub when: Option<SourceCondition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_condition: Option<OwnedFieldCondition>,
    pub slot: NativeOwnedSlot,
    pub location: OwnedLocation,
    pub collection: bool,
    pub hash_field: Option<crate::KeySelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<crate::FieldContract>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OwnedFieldCondition {
    pub pointer: String,
    pub when: crate::FieldCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSurface {
    ApiResponse,
    DependencyRequest,
    DependencyResponse,
    ApiInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum NativeOwnedSlot {
    Body,
    SseData(crate::SseSelector),
    Value,
    Key,
    RedisArgument(usize),
    SqlValue(usize),
    SqlColumn(String),
    SqlField(String),
    RedisValue(crate::RedisContainer),
    Header(String),
    Query(String),
    SocketIoConnect(String),
    PathSegment(usize),
    MultipartBoundary,
}

impl NativeOwnedSlot {
    fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SseData(a), Self::SseData(b)) => a.overlaps(b),
            (Self::SqlField(a), Self::SqlField(b)) => a.eq_ignore_ascii_case(b),
            (Self::RedisValue(_), Self::RedisValue(_) | Self::Value | Self::RedisArgument(_))
            | (Self::Value | Self::RedisArgument(_), Self::RedisValue(_)) => true,
            (Self::SqlField(_), Self::SqlValue(_) | Self::SqlColumn(_))
            | (Self::SqlValue(_) | Self::SqlColumn(_), Self::SqlField(_)) => true,
            _ => self == other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OwnedLocation {
    Scalar,
    HeaderParameter {
        name: String,
    },
    JsonPointer {
        pointer: String,
    },
    Protobuf {
        field_path: Vec<u32>,
        element: Option<OwnedElement>,
    },
    Hessian2 {
        value_path: Vec<String>,
    },
    Docx {
        part: String,
        element: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "index", rename_all = "snake_case")]
pub enum OwnedElement {
    Any,
    Index(usize),
}

mod contracts;
mod validation;
pub use validation::validate_field_claims;
pub use validation::value_sql_scopes_overlap;
pub use validation::value_sql_slots_overlap;

pub fn native_field_claims(rule: &NativeRule) -> Vec<NativeFieldClaim> {
    use ClaimSurface as S;
    use NativeOwnedSlot as L;
    let mut claims = vec![];
    let operation_override = Cell::new(None);
    let field_condition = match &rule.effect {
        NativeEffect::Identity(IdentityEffect {
            capture:
                IdentityCapture::RedisArgument {
                    when: Some(when),
                    json_pointer: Some(pointer),
                    ..
                },
            ..
        }) => when
            .peer_pointer(pointer)
            .map(|pointer| OwnedFieldCondition {
                pointer,
                when: when.clone(),
            }),
        _ => None,
    };
    let mut add = |surface, slot, location, collection| {
        claims.push(NativeFieldClaim {
            hash_field: match &rule.effect {
                NativeEffect::FiniteSharing(FiniteSharingEffect::Redis {
                    hash_field: Some(value),
                    ..
                }) => Some(crate::KeySelector {
                    exact: Some(value.clone()),
                    ..Default::default()
                }),
                _ => None,
            },
            rule_id: rule.id.clone(),
            surface,
            selector: {
                let mut selector = rule.selector.clone();
                if let Some(operation) = operation_override.get() {
                    selector.operation = Some(String::from(operation));
                }
                selector
            },
            when: rule.when.clone(),
            field_condition: field_condition.clone(),
            slot,
            location,
            collection,
            contract: None,
        })
    };
    match &rule.effect {
        NativeEffect::Identity(effect) => {
            let (slot, location) = match &effect.capture {
                IdentityCapture::MysqlValue {
                    index,
                    json_pointer,
                } => (
                    L::SqlValue(*index),
                    json_pointer
                        .as_deref()
                        .map(json)
                        .unwrap_or(OwnedLocation::Scalar),
                ),
                IdentityCapture::RedisArgument {
                    index,
                    json_pointer,
                    ..
                } => (
                    redis_argument(
                        rule.selector.operation.as_deref().unwrap_or_default(),
                        *index,
                    ),
                    json_pointer
                        .as_deref()
                        .map(json)
                        .unwrap_or(OwnedLocation::Scalar),
                ),
                IdentityCapture::HttpJson { pointer } => (L::Body, json(pointer)),
                IdentityCapture::HttpPath { segment } => {
                    (L::PathSegment(segment.index), OwnedLocation::Scalar)
                }
            };
            add(S::DependencyRequest, slot, location, false);
            if let IdentityCapture::RedisArgument { index, copies, .. } = &effect.capture {
                let slot = redis_argument(
                    rule.selector.operation.as_deref().unwrap_or_default(),
                    *index,
                );
                for copy in copies {
                    add(
                        S::DependencyRequest,
                        slot.clone(),
                        json(&copy.contract.pointer),
                        false,
                    );
                }
            }
        }
        NativeEffect::RedisSequence(effect) => {
            if effect.key.is_some() {
                add(S::DependencyRequest, L::Key, OwnedLocation::Scalar, false);
            }
            for command in &effect.commands {
                operation_override.set(Some(command.operation.as_str()));
                for (index, argument) in &command.arguments {
                    let slot = redis_argument(&command.operation, *index);
                    match &argument.contract {
                        SequenceArgument::Time(_) => {
                            add(S::DependencyRequest, slot, OwnedLocation::Scalar, false)
                        }
                        SequenceArgument::Json { fields } => {
                            for pointer in fields.keys() {
                                add(S::DependencyRequest, slot.clone(), json(pointer), false);
                            }
                        }
                    }
                }
            }
            operation_override.set(None);
        }
        NativeEffect::ResponseJwt(effect) => {
            if let Some(location) = &effect.location {
                add(
                    S::ApiResponse,
                    L::Header(location.header.to_ascii_lowercase()),
                    OwnedLocation::Scalar,
                    false,
                );
                return claims;
            }
            for pointer in std::iter::once(&effect.pointer)
                .chain(effect.expires_at.iter())
                .chain(effect.issued_at.iter())
                .chain(effect.ttl.iter())
            {
                add(S::ApiResponse, L::Body, json(pointer), false);
            }
        }
        NativeEffect::ResponseHeaderDate(effect) => add(
            S::ApiResponse,
            L::Header(effect.header.to_ascii_lowercase()),
            effect
                .parameter
                .as_deref()
                .map(|name| OwnedLocation::HeaderParameter {
                    name: name.trim_end_matches('*').to_ascii_lowercase(),
                })
                .unwrap_or(OwnedLocation::Scalar),
            false,
        ),
        NativeEffect::ResponseGenerated(effect) => {
            for pointer in effect.fields.keys() {
                add(S::ApiResponse, L::Body, json(pointer), false);
            }
        }
        NativeEffect::ResponseBody(effect) => {
            for field in &effect.fields {
                let (location, collection) = match &field.contract {
                    BodyField::Unordered { selector } => (body_location(selector), true),
                    BodyField::JoinedString { selector, .. } => (body_location(selector), false),
                    BodyField::Timestamp { part, element, .. } => (
                        OwnedLocation::Docx {
                            part: part.clone(),
                            element: element.clone(),
                        },
                        false,
                    ),
                };
                add(S::ApiResponse, L::Body, location, collection);
            }
        }
        NativeEffect::HttpRequest(effect) => {
            for parameter in effect.query.keys() {
                add(
                    S::DependencyRequest,
                    L::Query(parameter.clone()),
                    OwnedLocation::Scalar,
                    false,
                );
            }
            if effect.multipart_boundary {
                add(
                    S::DependencyRequest,
                    L::MultipartBoundary,
                    OwnedLocation::Scalar,
                    false,
                );
            }
        }
        NativeEffect::MysqlValues(effect) => {
            for index in effect.params.keys() {
                add(
                    S::DependencyRequest,
                    L::SqlValue(*index),
                    OwnedLocation::Scalar,
                    false,
                );
            }
            for (index, value) in &effect.values {
                match &value.contract {
                    SqlValueContract::Time(_) => add(
                        S::DependencyRequest,
                        L::SqlValue(*index),
                        OwnedLocation::Scalar,
                        false,
                    ),
                    SqlValueContract::Json { fields } => {
                        for pointer in fields.keys() {
                            add(
                                S::DependencyRequest,
                                L::SqlValue(*index),
                                json(pointer),
                                false,
                            );
                        }
                    }
                }
            }
        }
        NativeEffect::InputJwt(effect) => {
            let (slot, location) = match &effect.location {
                InputTokenLocation::BearerHeader { name }
                | InputTokenLocation::RawHeader { name } => {
                    (L::Header(name.to_ascii_lowercase()), OwnedLocation::Scalar)
                }
                InputTokenLocation::Query { name } => {
                    (L::Query(name.clone()), OwnedLocation::Scalar)
                }
                InputTokenLocation::SocketIoConnect { namespace, pointer } => {
                    (L::SocketIoConnect(namespace.clone()), json(pointer))
                }
            };
            add(S::ApiInput, slot, location, false);
        }
        NativeEffect::InputSignedTimestamp(effect) => {
            // Stable signed fields must also be protected from another input
            // transform; otherwise that transform would invalidate this signature.
            for pointer in effect
                .fields
                .values()
                .chain(std::iter::once(&effect.signature_pointer))
            {
                add(S::ApiInput, L::Body, json(pointer), false);
            }
        }
        NativeEffect::FiniteSharing(_)
        | NativeEffect::CaptureHttp(_)
        | NativeEffect::CaptureHttpResponse(_)
        | NativeEffect::ProcessOwned(_) => (),
    }
    for claim in &mut claims {
        claim.contract = contracts::native_contract(rule, claim);
    }
    claims
}

fn redis_argument(operation: &str, index: usize) -> NativeOwnedSlot {
    if matches!(
        (operation, index),
        ("SET" | "PUBLISH", 1) | ("SETEX" | "PSETEX", 2)
    ) {
        NativeOwnedSlot::Value
    } else {
        NativeOwnedSlot::RedisArgument(index)
    }
}

fn json(pointer: &str) -> OwnedLocation {
    OwnedLocation::JsonPointer {
        pointer: pointer.into(),
    }
}

fn body_location(selector: &BodySelector) -> OwnedLocation {
    match selector {
        BodySelector::Json { pointer } => json(pointer),
        BodySelector::Protobuf { field_path, .. } => OwnedLocation::Protobuf {
            field_path: field_path.clone(),
            element: None,
        },
        BodySelector::Hessian2 { value_path, .. } => OwnedLocation::Hessian2 {
            value_path: value_path.clone(),
        },
    }
}
