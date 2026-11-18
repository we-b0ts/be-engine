//! One conservative ownership check covers native and ordinary value effects.
use anyhow::{Context, Result};

use super::*;
use crate::{
    Codec, CompiledNativeRule, CompiledRule, FieldContract, KeySelector, MatchSpec, Slot, Surface,
};

fn implicit_identity_delivery(rule: &CompiledRule) -> bool {
    rule.rule.surface == Surface::DependencyResponse
        && rule
            .rule
            .contract
            .values()
            .any(|field| matches!(field.unconditional(), FieldContract::Identity { .. }))
}

pub fn validate_field_claims(
    value: &[CompiledRule],
    native: &[CompiledNativeRule],
    context: &crate::CompilationContext<'_>,
) -> Result<()> {
    validate_body_codecs(value, native, context)?;
    let redis_read_back = native
        .iter()
        .filter(|rule| !rule.rule.effect.redis_read_back().is_empty())
        .map(|rule| rule.rule.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let identity_read_back = native
        .iter()
        .filter(|rule| !rule.rule.effect.redis_read_back().is_empty())
        .map(|rule| rule.rule.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let delivery = value
        .iter()
        .filter(|rule| rule.rule.delivery.is_some())
        .map(|rule| rule.rule.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let identity_delivery = value
        .iter()
        .filter(|rule| implicit_identity_delivery(rule))
        .map(|rule| rule.rule.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let observations = value
        .iter()
        .filter(|rule| {
            rule.rule.surface == Surface::DependencyResponse
                && matches!(rule.rule.slot, Slot::SqlField(_) | Slot::RedisValue(_))
                && rule.delivery_time.is_empty()
                && !implicit_identity_delivery(rule)
        })
        .map(|rule| rule.rule.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut claims = vec![];
    for compiled in value {
        claims.extend(value_claims(compiled, context)?);
    }
    for compiled in native {
        claims.extend(native_field_claims(&compiled.rule));
    }
    for (index, claim) in claims.iter().enumerate() {
        for other in &claims[..index] {
            if claim.surface != other.surface
                || !claim.slot.overlaps(&other.slot)
                || !crate::compiler::key_scopes_overlap(
                    claim.hash_field.as_ref(),
                    other.hash_field.as_ref(),
                )
                || !scopes_overlap(&claim.selector, &other.selector)?
                || !physical_slots_overlap(claim, other)
                || crate::compiler::disjoint_conditions(claim.when.as_ref(), other.when.as_ref())
            {
                continue;
            }
            if let (Some(a), Some(b)) = (&claim.field_condition, &other.field_condition)
                && a.pointer == b.pointer
                && a.when.disjoint(&b.when)
            {
                continue;
            }
            if super::read_commutation::compatible_read_back(native, claim, other) {
                continue;
            }
            if observations.contains(claim.rule_id.as_str())
                && redis_read_back.contains(other.rule_id.as_str())
                || observations.contains(other.rule_id.as_str())
                    && redis_read_back.contains(claim.rule_id.as_str())
            {
                continue;
            }
            anyhow::ensure!(
                claim.surface != ClaimSurface::DependencyResponse
                    || !(redis_read_back.contains(claim.rule_id.as_str())
                        && delivery.contains(other.rule_id.as_str())
                        || redis_read_back.contains(other.rule_id.as_str())
                            && delivery.contains(claim.rule_id.as_str())
                        || identity_read_back.contains(claim.rule_id.as_str())
                            && identity_delivery.contains(other.rule_id.as_str())
                        || identity_read_back.contains(other.rule_id.as_str())
                            && identity_delivery.contains(claim.rule_id.as_str())),
                "native read_back cannot share a response with another delivery owner: {:?} / {:?}",
                claim.rule_id,
                other.rule_id
            );
            let overlap = locations_overlap(&claim.location, &other.location);
            if overlap && equivalent_context(value, native, claim, other) {
                continue;
            }
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

fn equivalent_context(
    value: &[CompiledRule],
    native: &[CompiledNativeRule],
    left: &NativeFieldClaim,
    right: &NativeFieldClaim,
) -> bool {
    let (declared, contextual) = if value.iter().any(|rule| {
        rule.rule.id == left.rule_id
            && matches!(rule.rule.slot, Slot::SqlField(_) | Slot::RedisValue(_))
    }) {
        (left, right)
    } else if value.iter().any(|rule| {
        rule.rule.id == right.rule_id
            && matches!(rule.rule.slot, Slot::SqlField(_) | Slot::RedisValue(_))
    }) {
        (right, left)
    } else {
        return false;
    };
    if !native.iter().any(|rule| rule.rule.id == contextual.rule_id) {
        return false;
    }
    if declared.location != contextual.location {
        return false;
    }
    if !super::contracts::same_position(declared, contextual) {
        return false;
    }
    let (Some(declared_contract), Some(contextual_contract)) =
        (&declared.contract, &contextual.contract)
    else {
        return false;
    };
    super::contracts::same_strategy(declared_contract, contextual_contract)
}

/// Container/child composition is valid only with one common typed codec view.
/// A wire field cannot acquire a second alias in a separate rule.
fn validate_body_codecs(
    value: &[CompiledRule],
    native: &[CompiledNativeRule],
    context: &crate::CompilationContext<'_>,
) -> Result<()> {
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
            crate::NativeEffect::ResponseBody(effect) => effect
                .value_codec(context.codecs)?
                .map(|codec| (Surface::ApiResponse, codec)),
            crate::NativeEffect::ResponseGenerated(_) => Some((Surface::ApiResponse, Codec::Json)),
            crate::NativeEffect::ResponseJwt(effect) if effect.location.is_none() => {
                Some((Surface::ApiResponse, Codec::Json))
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
                || crate::compiler::disjoint_conditions(when.as_ref(), other_when.as_ref())
            {
                continue;
            }
            let mut merged = codec.clone();
            crate::compiler::merge_codec(&mut merged, other_codec, context)?;
            crate::compiler::validate_codec(&merged, context)?;
        }
    }
    Ok(())
}

pub fn value_claims(
    compiled: &CompiledRule,
    context: &crate::CompilationContext<'_>,
) -> Result<Vec<NativeFieldClaim>> {
    let rule = &compiled.rule;
    rule.contract
        .iter()
        .map(|(pointer, contract)| {
            let location = if rule.codec == Codec::Scalar {
                OwnedLocation::Scalar
            } else if let Some(codec) =
                crate::native_compile::codec_binding::protobuf_schema(&rule.codec)
            {
                let field = codec
                    .field(pointer)
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
            } else {
                OwnedLocation::JsonPointer {
                    pointer: pointer.clone(),
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
                    Slot::SqlField(name) => NativeOwnedSlot::SqlField(name.clone()),
                    Slot::RedisValue(container) => NativeOwnedSlot::RedisValue(*container),
                },
                location,
                collection: contract.supports_child_rules(context.policies)?,
                contract: Some(contract.clone()),
            })
        })
        .collect()
}

fn selector(value: &MatchSpec) -> NativeMatch {
    NativeMatch {
        api: value.api.clone(),
        resource: value.resource.clone(),
        http_host: None,
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
    if left
        .resource
        .as_ref()
        .is_some_and(|r| r.protocol == crate::Protocol::Mysql)
        && right
            .resource
            .as_ref()
            .is_some_and(|r| r.protocol == crate::Protocol::Mysql)
        && (left.sql.is_none() || right.sql.is_none())
    {
        let matcher = |selector: &NativeMatch| {
            (!selector.tables.is_empty()
                || !selector.table_patterns.is_empty()
                || selector.table_series.is_some())
            .then(|| {
                traffic_protocol_mysql::table_selector::TableMatcher::new(
                    &selector.tables,
                    &selector.table_patterns,
                    selector.table_series.as_ref(),
                )
            })
            .transpose()
        };
        if let (Some(a), Some(b)) = (matcher(left)?, matcher(right)?) {
            return Ok(a.overlaps(&b));
        }
    }
    let (Some(a), Some(b)) = (&left.sql, &right.sql) else {
        return Ok(true);
    };
    const MARKER: &str = "__traffic_native_claim_table__";
    let (a, b) = (
        traffic_protocol_mysql::sql::tokens(&a.replace("{{table}}", MARKER))
            .context("invalid native SQL ownership selector")?,
        traffic_protocol_mysql::sql::tokens(&b.replace("{{table}}", MARKER))
            .context("invalid native SQL ownership selector")?,
    );
    let tables = |selector: &NativeMatch| {
        (!selector.tables.is_empty()
            || !selector.table_patterns.is_empty()
            || selector.table_series.is_some())
        .then(|| {
            traffic_protocol_mysql::table_selector::TableMatcher::new(
                &selector.tables,
                &selector.table_patterns,
                selector.table_series.as_ref(),
            )
        })
        .transpose()
    };
    let (left, right) = (tables(left)?, tables(right)?);
    Ok(traffic_protocol_mysql::sql::table_template::overlap(
        &a,
        left.as_ref().map(|_| MARKER),
        &b,
        right.as_ref().map(|_| MARKER),
    )
    .is_some_and(|constraints| {
        constraints.compatible(
            |table| left.as_ref().is_some_and(|tables| tables.matches(table)),
            |table| right.as_ref().is_some_and(|tables| tables.matches(table)),
            || matches!((&left, &right), (Some(left), Some(right)) if left.overlaps(right)),
        )
    }))
}

pub fn value_sql_scopes_overlap(left: &MatchSpec, right: &MatchSpec) -> bool {
    sql_overlap(&selector(left), &selector(right)).unwrap_or(true)
}

pub fn value_sql_slots_overlap(left: &crate::Rule, right: &crate::Rule) -> bool {
    let slot = |slot: &Slot| match slot {
        Slot::SqlField(name) => Some(NativeOwnedSlot::SqlField(name.clone())),
        Slot::SqlValue(index) => Some(NativeOwnedSlot::SqlValue(*index)),
        Slot::SqlColumn(name) => Some(NativeOwnedSlot::SqlColumn(name.clone())),
        _ => None,
    };
    match (slot(&left.slot), slot(&right.slot)) {
        (Some(a), Some(b)) => sql_slots_overlap(
            &selector(&left.selector),
            &a,
            &selector(&right.selector),
            &b,
        ),
        _ => true,
    }
}

fn physical_slots_overlap(left: &NativeFieldClaim, right: &NativeFieldClaim) -> bool {
    redis_slots_overlap(left, right)
        && sql_slots_overlap(&left.selector, &left.slot, &right.selector, &right.slot)
}

fn redis_slots_overlap(left: &NativeFieldClaim, right: &NativeFieldClaim) -> bool {
    use crate::RedisContainer;
    let (container, selected) = match (&left.slot, &right.slot) {
        (NativeOwnedSlot::RedisValue(a), NativeOwnedSlot::RedisValue(b)) => return a == b,
        (NativeOwnedSlot::RedisValue(container), _) => (container, right),
        (_, NativeOwnedSlot::RedisValue(container)) => (container, left),
        _ => return true,
    };
    let Some(operation) = selected.selector.operation.as_deref() else {
        return true;
    };
    match (selected.surface, container) {
        (ClaimSurface::DependencyRequest, RedisContainer::String) => {
            matches!(operation, "SET" | "SETEX" | "PSETEX" | "MSET")
        }
        (ClaimSurface::DependencyRequest, RedisContainer::Hash) => {
            matches!(operation, "HSET" | "HMSET")
        }
        (ClaimSurface::DependencyRequest, RedisContainer::List) => {
            matches!(operation, "RPUSH" | "LPUSH" | "LSET")
        }
        (ClaimSurface::DependencyResponse, RedisContainer::String) => {
            matches!(operation, "GET" | "MGET")
        }
        (ClaimSurface::DependencyResponse, RedisContainer::Hash) => {
            matches!(operation, "HGET" | "HMGET" | "HGETALL")
        }
        (ClaimSurface::DependencyResponse, RedisContainer::List) => {
            matches!(operation, "LRANGE" | "LINDEX")
        }
        _ => false,
    }
}

fn sql_slots_overlap(
    left: &NativeMatch,
    left_slot: &NativeOwnedSlot,
    right: &NativeMatch,
    right_slot: &NativeOwnedSlot,
) -> bool {
    let (physical, column, selected, slot) = match (left_slot, right_slot) {
        (
            NativeOwnedSlot::SqlField(column),
            NativeOwnedSlot::SqlValue(_) | NativeOwnedSlot::SqlColumn(_),
        ) => (left, column, right, right_slot),
        (
            NativeOwnedSlot::SqlValue(_) | NativeOwnedSlot::SqlColumn(_),
            NativeOwnedSlot::SqlField(column),
        ) => (right, column, left, left_slot),
        _ => return true,
    };
    let Some(sql) = &selected.sql else {
        return true;
    };
    const MARKER: &str = "__traffic_field_table__";
    let template_marker = sql.contains("{{table}}") && !sql.contains(MARKER);
    let Some(tokens) =
        traffic_protocol_mysql::sql::bounds::statement(&sql.replace("{{table}}", MARKER))
    else {
        return true;
    };
    let database = selected
        .resource
        .as_ref()
        .and_then(|r| r.database.as_ref())
        .and_then(crate::Database::name);
    let matches = |field: &traffic_protocol_mysql::sql::field_bindings::FieldIdentity| {
        field.column.eq_ignore_ascii_case(column)
            && physical
                .resource
                .as_ref()
                .and_then(|r| r.database.as_ref())
                .and_then(crate::Database::name)
                .zip(field.database.as_deref())
                .is_none_or(|(a, b)| a == b)
            && (template_marker && field.table == MARKER
                || traffic_protocol_mysql::table_selector::TableMatcher::new(
                    &physical.tables,
                    &physical.table_patterns,
                    physical.table_series.as_ref(),
                )
                .map_or(true, |tables| tables.matches(&field.table)))
    };
    match slot {
        NativeOwnedSlot::SqlValue(index) => {
            let Some(position) = tokens
                .iter()
                .enumerate()
                .filter(|(_, token)| {
                    matches!(token, traffic_protocol_mysql::sql::Token::Placeholder)
                })
                .nth(*index)
                .map(|(index, _)| index)
            else {
                return true;
            };
            traffic_protocol_mysql::sql::field_bindings::resolve(&tokens, database).is_none_or(
                |bindings| {
                    let fields = bindings
                        .iter()
                        .filter(|binding| binding.token_index == position)
                        .collect::<Vec<_>>();
                    fields.is_empty() || fields.into_iter().any(|binding| matches(&binding.field))
                },
            )
        }
        NativeOwnedSlot::SqlColumn(name) => {
            traffic_protocol_mysql::sql::field_bindings::projection_columns(&tokens, database)
                .is_none_or(|columns| {
                    let originals = columns
                        .iter()
                        .filter(|(_, field)| {
                            field
                                .as_ref()
                                .is_some_and(|field| field.column.eq_ignore_ascii_case(name))
                        })
                        .collect::<Vec<_>>();
                    let candidates = if originals.is_empty() {
                        columns
                            .iter()
                            .filter(|(label, _)| label.eq_ignore_ascii_case(name))
                            .collect::<Vec<_>>()
                    } else {
                        originals
                    };
                    candidates.is_empty()
                        || candidates
                            .iter()
                            .any(|(_, field)| field.as_ref().is_none_or(matches))
                })
        }
        _ => true,
    }
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
    left == right || traffic_protocol_http::path_pattern::path_patterns_overlap(left, right)
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
