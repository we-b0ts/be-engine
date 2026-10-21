//! One conservative ownership check covers native and ordinary value effects.
use anyhow::{Context, Result};

use super::*;
use crate::policy::{
    Codec, CompiledNativeRule, CompiledRule, FieldContract, KeySelector, MatchSpec, Slot, Surface,
};

pub fn validate_field_claims(value: &[CompiledRule], native: &[CompiledNativeRule]) -> Result<()> {
    validate_body_codecs(value, native)?;
    let read_back = native
        .iter()
        .filter(|rule| !rule.rule.effect.redis_read_back().is_empty())
        .map(|rule| rule.rule.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let delivery = value
        .iter()
        .filter(|rule| rule.rule.delivery.is_some())
        .map(|rule| rule.rule.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut claims = vec![];
    for compiled in value {
        claims.extend(value_claims(compiled)?);
    }
    for compiled in native {
        claims.extend(native_field_claims(&compiled.rule));
    }
    for (index, claim) in claims.iter().enumerate() {
        for other in &claims[..index] {
            if claim.surface != other.surface
                || !claim.slot.overlaps(&other.slot)
                || !crate::policy::compiler::key_scopes_overlap(
                    claim.hash_field.as_ref(),
                    other.hash_field.as_ref(),
                )
                || !scopes_overlap(&claim.selector, &other.selector)?
                || crate::policy::compiler::disjoint_conditions(
                    claim.when.as_ref(),
                    other.when.as_ref(),
                )
            {
                continue;
            }
            if let (Some(a), Some(b)) = (&claim.field_condition, &other.field_condition)
                && a.pointer == b.pointer
                && a.when.disjoint(&b.when)
            {
                continue;
            }
            anyhow::ensure!(
                claim.surface != ClaimSurface::DependencyResponse
                    || !(read_back.contains(claim.rule_id.as_str())
                        && delivery.contains(other.rule_id.as_str())
                        || read_back.contains(other.rule_id.as_str())
                            && delivery.contains(claim.rule_id.as_str())),
                "Redis read_back cannot share a response with another delivery owner: {:?} / {:?}",
                claim.rule_id,
                other.rule_id
            );
            let overlap = locations_overlap(&claim.location, &other.location);
            if overlap && !container_child(claim, other) && !container_child(other, claim) {
                anyhow::bail!(
                    "field ownership conflicts between rules {:?} and {:?} in {:?}: {:?} / {:?}",
                    claim.rule_id,
                    other.rule_id,
                    claim.slot,
                    claim.location,
                    other.location
                );
            }
        }
    }
    Ok(())
}

/// Container/child composition is valid only with one common typed codec view.
/// A wire field cannot acquire a second alias in a separate rule.
fn validate_body_codecs(value: &[CompiledRule], native: &[CompiledNativeRule]) -> Result<()> {
    let mut codecs = value
        .iter()
        .filter(|compiled| compiled.rule.slot == Slot::Body)
        .map(|compiled| {
            (
                compiled.rule.surface,
                selector(&compiled.rule.selector),
                compiled.rule.when.clone(),
                compiled.rule.codec.clone(),
            )
        })
        .collect::<Vec<_>>();
    for compiled in native {
        let codec = match &compiled.rule.effect {
            crate::policy::NativeEffect::ResponseBody(effect) => effect
                .value_codec()?
                .map(|codec| (Surface::ApiResponse, codec)),
            crate::policy::NativeEffect::ResponseGenerated(_) => {
                Some((Surface::ApiResponse, Codec::Json))
            }
            crate::policy::NativeEffect::ResponseJwt(effect) if effect.location.is_none() => {
                Some((Surface::ApiResponse, Codec::Json))
            }
            crate::policy::NativeEffect::HttpRequest(effect) if !effect.json.is_empty() => {
                Some((Surface::DependencyRequest, Codec::Json))
            }
            _ => None,
        };
        if let Some((surface, codec)) = codec {
            codecs.push((
                surface,
                compiled.rule.selector.clone(),
                compiled.rule.when.clone(),
                codec,
            ));
        }
    }
    for (index, (surface, scope, when, codec)) in codecs.iter().enumerate() {
        for (other_surface, other_scope, other_when, other_codec) in &codecs[..index] {
            if surface != other_surface
                || !scopes_overlap(scope, other_scope)?
                || crate::policy::compiler::disjoint_conditions(when.as_ref(), other_when.as_ref())
            {
                continue;
            }
            let mut merged = codec.clone();
            crate::value_contract::encoded::merge_codec(&mut merged, other_codec)?;
            crate::policy::compiler::validate_codec(&merged)?;
        }
    }
    Ok(())
}

fn value_claims(compiled: &CompiledRule) -> Result<Vec<NativeFieldClaim>> {
    let rule = &compiled.rule;
    rule.contract
        .iter()
        .map(|(pointer, contract)| {
            let location = match &rule.codec {
                Codec::Json => OwnedLocation::JsonPointer {
                    pointer: pointer.clone(),
                },
                Codec::Protobuf(codec) => {
                    let field = crate::policy::resolve_protobuf_field(codec, pointer)
                        .context("compiled Protobuf field has no typed binding")?;
                    let element = if codec.fields.contains_key(pointer) {
                        None
                    } else {
                        let (_, element) = pointer
                            .rsplit_once('/')
                            .context("invalid bound scalar element")?;
                        Some(if element == "*" {
                            OwnedElement::Any
                        } else {
                            OwnedElement::Index(element.parse()?)
                        })
                    };
                    OwnedLocation::Protobuf {
                        field_path: field.field_path,
                        element,
                    }
                }
            };
            Ok(NativeFieldClaim {
                hash_field: rule.selector.hash_field.clone(),
                rule_id: rule.id.clone(),
                surface: match rule.surface {
                    Surface::ApiResponse => ClaimSurface::ApiResponse,
                    Surface::DependencyRequest => ClaimSurface::DependencyRequest,
                    Surface::DependencyResponse => ClaimSurface::DependencyResponse,
                },
                selector: selector(&rule.selector),
                when: rule.when.clone(),
                field_condition: None,
                slot: match &rule.slot {
                    Slot::Body => NativeOwnedSlot::Body,
                    Slot::SseData(event) => NativeOwnedSlot::SseData(event.clone()),
                    Slot::Value => NativeOwnedSlot::Value,
                    Slot::SqlValue(index) => NativeOwnedSlot::SqlValue(*index),
                    Slot::SqlColumn(name) => NativeOwnedSlot::SqlColumn(name.clone()),
                },
                location,
                collection: matches!(contract, FieldContract::Unordered),
            })
        })
        .collect()
}

fn selector(value: &MatchSpec) -> NativeMatch {
    NativeMatch {
        api: value.api.clone(),
        resource: value.resource.clone(),
        operation: value.operation.clone(),
        key: value.key.as_ref().map(key),
        path: value.path.clone(),
        sql: value.sql.clone(),
        tables: value.tables.clone(),
        table_patterns: value.table_patterns.clone(),
        table_series: value.table_series.clone(),
    }
}

fn key(value: &KeySelector) -> NativeKeySelector {
    if let Some(value) = &value.exact {
        NativeKeySelector::Exact {
            value: value.clone(),
        }
    } else if value.numeric {
        NativeKeySelector::Numeric {
            prefix: value.prefix.clone().unwrap_or_default(),
            suffix: value.suffix.clone().unwrap_or_default(),
        }
    } else {
        NativeKeySelector::Affix {
            prefix: value.prefix.clone().unwrap_or_default(),
            suffix: value.suffix.clone().unwrap_or_default(),
        }
    }
}

fn scopes_overlap(left: &NativeMatch, right: &NativeMatch) -> Result<bool> {
    if let (Some(left), Some(right)) = (&left.resource, &right.resource)
        && (left.protocol != right.protocol
            || !left
                .endpoint
                .host
                .eq_ignore_ascii_case(&right.endpoint.host)
            || left.endpoint.port != right.endpoint.port
            || disjoint(left.database.as_ref(), right.database.as_ref())
            || disjoint(left.username.as_ref(), right.username.as_ref()))
    {
        return Ok(false);
    }
    if disjoint(left.operation.as_ref(), right.operation.as_ref())
        || !paths_overlap(left.api.as_deref(), right.api.as_deref(), true)
        || !paths_overlap(left.path.as_deref(), right.path.as_deref(), false)
    {
        return Ok(false);
    }
    if let (Some(left), Some(right)) = (&left.key, &right.key)
        && !keys_overlap(left, right)
    {
        return Ok(false);
    }
    sql_overlap(left, right)
}

fn sql_overlap(left: &NativeMatch, right: &NativeMatch) -> Result<bool> {
    let (Some(a), Some(b)) = (&left.sql, &right.sql) else {
        return Ok(true);
    };
    const MARKER: &str = "__traffic_native_claim_table__";
    let (a, b) = (
        crate::mysql::sql::tokens(&a.replace("{{table}}", MARKER))
            .context("invalid native SQL ownership selector")?,
        crate::mysql::sql::tokens(&b.replace("{{table}}", MARKER))
            .context("invalid native SQL ownership selector")?,
    );
    if a.len() != b.len() {
        return Ok(false);
    }
    let tables = |selector: &NativeMatch| {
        crate::config::mysql_tables::TableMatcher::new(
            &selector.tables,
            &selector.table_patterns,
            selector.table_series.as_ref(),
        )
    };
    use crate::mysql::sql::Token;
    for (a, b) in a.iter().zip(&b) {
        if a.is(MARKER) && b.is(MARKER) {
            if !tables(left)?.overlaps(&tables(right)?) {
                return Ok(false);
            }
        } else if a.is(MARKER) {
            let Token::Word(table) = b else {
                return Ok(false);
            };
            if !tables(left)?.matches(table) {
                return Ok(false);
            }
        } else if b.is(MARKER) {
            let Token::Word(table) = a else {
                return Ok(false);
            };
            if !tables(right)?.matches(table) {
                return Ok(false);
            }
        } else if a != b
            && !(*a == Token::Placeholder && b.is_value())
            && !(*b == Token::Placeholder && a.is_value())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn value_sql_scopes_overlap(left: &MatchSpec, right: &MatchSpec) -> bool {
    sql_overlap(&selector(left), &selector(right)).unwrap_or(true)
}

fn disjoint<T: PartialEq>(left: Option<&T>, right: Option<&T>) -> bool {
    matches!((left,right),(Some(left),Some(right))if left!=right)
}

fn paths_overlap(left: Option<&str>, right: Option<&str>, api: bool) -> bool {
    let (Some(mut left), Some(mut right)) = (left, right) else {
        return true;
    };
    if api {
        let (Some((a, path_a)), Some((b, path_b))) = (left.split_once(' '), right.split_once(' '))
        else {
            return true;
        };
        if a != b {
            return false;
        }
        left = path_a;
        right = path_b;
    }
    left == right || crate::path_pattern::path_patterns_overlap(left, right)
}

fn keys_overlap(left: &NativeKeySelector, right: &NativeKeySelector) -> bool {
    fn accepts(selector: &NativeKeySelector, value: &str) -> bool {
        match selector {
            NativeKeySelector::Exact { value: expected } => expected == value,
            NativeKeySelector::Affix { prefix, suffix } => {
                value.starts_with(prefix) && value.ends_with(suffix)
            }
            NativeKeySelector::Numeric { prefix, suffix } => value
                .strip_prefix(prefix)
                .and_then(|s| s.strip_suffix(suffix))
                .is_some_and(|middle| {
                    !middle.is_empty() && middle.bytes().all(|b| b.is_ascii_digit())
                }),
        }
    }
    match (left, right) {
        (NativeKeySelector::Exact { value }, other)
        | (other, NativeKeySelector::Exact { value }) => accepts(other, value),
        (
            NativeKeySelector::Affix {
                prefix: a,
                suffix: b,
            }
            | NativeKeySelector::Numeric {
                prefix: a,
                suffix: b,
            },
            NativeKeySelector::Affix {
                prefix: c,
                suffix: d,
            }
            | NativeKeySelector::Numeric {
                prefix: c,
                suffix: d,
            },
        ) => (a.starts_with(c) || c.starts_with(a)) && (b.ends_with(d) || d.ends_with(b)),
    }
}

fn locations_overlap(left: &OwnedLocation, right: &OwnedLocation) -> bool {
    use OwnedLocation as L;
    match (left, right) {
        (L::Scalar, _) | (_, L::Scalar) => true,
        (L::JsonPointer { pointer: a }, L::JsonPointer { pointer: b }) => prefix_overlap(
            &a.split('/').skip(1).collect::<Vec<_>>(),
            &b.split('/').skip(1).collect::<Vec<_>>(),
        ),
        (
            L::Protobuf {
                field_path: a,
                element: x,
            },
            L::Protobuf {
                field_path: b,
                element: y,
            },
        ) => {
            if a == b {
                x.is_none()
                    || y.is_none()
                    || x == y
                    || matches!(x, Some(OwnedElement::Any))
                    || matches!(y, Some(OwnedElement::Any))
            } else {
                a.starts_with(b) || b.starts_with(a)
            }
        }
        (L::Hessian2 { value_path: a }, L::Hessian2 { value_path: b }) => prefix_overlap(
            &a.iter().map(String::as_str).collect::<Vec<_>>(),
            &b.iter().map(String::as_str).collect::<Vec<_>>(),
        ),
        (L::HeaderParameter { name: a }, L::HeaderParameter { name: b }) => a == b,
        (L::PayloadItem { index: a }, L::PayloadItem { index: b }) => a == b,
        (
            L::Docx {
                part: a,
                element: b,
            },
            L::Docx {
                part: c,
                element: d,
            },
        ) => a == c && b == d,
        // Two codecs cannot each own a different interpretation of one payload.
        _ => true,
    }
}

fn prefix_overlap(left: &[&str], right: &[&str]) -> bool {
    left.iter()
        .zip(right)
        .all(|(a, b)| a == b || *a == "*" || *b == "*")
}

fn container_child(parent: &NativeFieldClaim, child: &NativeFieldClaim) -> bool {
    if !parent.collection {
        return false;
    }
    match (&parent.location, &child.location) {
        (OwnedLocation::JsonPointer { pointer: a }, OwnedLocation::JsonPointer { pointer: b }) => {
            let a = a.split('/').skip(1).collect::<Vec<_>>();
            let b = b.split('/').skip(1).collect::<Vec<_>>();
            b.len() > a.len() && prefix_overlap(&a, &b[..a.len()]) && b[a.len()] == "*"
        }
        (
            OwnedLocation::Protobuf {
                field_path: a,
                element: None,
            },
            OwnedLocation::Protobuf {
                field_path: b,
                element,
            },
        ) => b.starts_with(a) && (b.len() > a.len() || element.is_some()),
        (OwnedLocation::Hessian2 { value_path: a }, OwnedLocation::Hessian2 { value_path: b }) => {
            b.len() > a.len() && b.starts_with(a) && b[a.len()] == "*"
        }
        _ => false,
    }
}
