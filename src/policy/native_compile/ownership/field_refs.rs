//! A field reference names a physical field, rather than borrowing a format.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};

use super::*;
use crate::policy::{CompiledNativeRule, CompiledRule, FieldReferenceUse, TrafficPolicy};

pub(crate) fn validate_field_references(
    document: &TrafficPolicy,
    origins: &BTreeMap<String, String>,
    value: &[CompiledRule],
    native: &[CompiledNativeRule],
) -> Result<()> {
    for (id, references) in &document.field_references {
        let rule = native
            .iter()
            .find(|rule| &rule.rule.id == id)
            .context("field_ref owner must remain a native rule")?;
        let claims = native_field_claims(&rule.rule);
        for usage in references {
            let reference = &usage.reference;
            let origin = match (&reference.table, &reference.column, reference.key) {
                (Some(table), Some(column), None) => format!(
                    "resources.{}.tables.{table}.fields.{column}",
                    reference.resource
                ),
                (None, None, Some(index)) => {
                    format!("resources.{}.keys[{index}].value", reference.resource)
                }
                _ => anyhow::bail!("field_ref requires one physical SQL or Redis location"),
            };
            let mut bound = false;
            for compiled in value
                .iter()
                .filter(|rule| origins.get(&rule.rule.id) == Some(&origin))
            {
                for declared in super::validation::value_claims(compiled)? {
                    if reference.pointer.as_deref().unwrap_or("")
                        != match &declared.location {
                            OwnedLocation::Scalar => "",
                            OwnedLocation::JsonPointer { pointer } => pointer,
                            _ => continue,
                        }
                    {
                        continue;
                    }
                    bound |= claims.iter().any(|contextual| {
                        usage_selects(usage, &rule.rule, contextual)
                            && declared.surface == contextual.surface
                            && declared.location == contextual.location
                            && same_resource(&declared.selector, &contextual.selector)
                            && scope_contains(&declared, contextual)
                            && super::contracts::same_position(&declared, contextual)
                    });
                }
            }
            ensure!(
                bound,
                "rule {id:?} field_ref at {:?} does not name its native physical field",
                usage.path
            );
        }
    }
    Ok(())
}

fn usage_selects(usage: &FieldReferenceUse, rule: &NativeRule, claim: &NativeFieldClaim) -> bool {
    let path = usage.path.iter().map(String::as_str).collect::<Vec<_>>();
    let (slot, location, surface, operation) = match path.as_slice() {
        ["effect", "values", index] => (
            NativeOwnedSlot::SqlValue(index.parse().unwrap_or(usize::MAX)),
            OwnedLocation::Scalar,
            ClaimSurface::DependencyRequest,
            None,
        ),
        ["effect", "values", index, "fields", pointer] => (
            NativeOwnedSlot::SqlValue(index.parse().unwrap_or(usize::MAX)),
            json(pointer),
            ClaimSurface::DependencyRequest,
            None,
        ),
        ["effect", "response_time", column, "time"] => (
            NativeOwnedSlot::SqlColumn((*column).into()),
            OwnedLocation::Scalar,
            ClaimSurface::DependencyResponse,
            None,
        ),
        ["effect", "response_time", pointer] => (
            NativeOwnedSlot::Value,
            json(pointer),
            ClaimSurface::DependencyResponse,
            None,
        ),
        ["effect", "commands", command, "arguments", index, rest @ ..] => {
            let NativeEffect::RedisSequence(effect) = &rule.effect else {
                return false;
            };
            let Some(command) = command
                .parse::<usize>()
                .ok()
                .and_then(|index| effect.commands.get(index))
            else {
                return false;
            };
            let Some(index) = index.parse::<usize>().ok() else {
                return false;
            };
            let location = match rest {
                [] => OwnedLocation::Scalar,
                ["fields", pointer] => json(pointer),
                _ => return false,
            };
            (
                redis_argument(&command.operation, index),
                location,
                ClaimSurface::DependencyRequest,
                Some(command.operation.as_str()),
            )
        }
        _ => return false,
    };
    claim.slot == slot
        && claim.location == location
        && claim.surface == surface
        && operation.is_none_or(|operation| claim.selector.operation.as_deref() == Some(operation))
}

fn same_resource(left: &NativeMatch, right: &NativeMatch) -> bool {
    left.resource
        .as_ref()
        .zip(right.resource.as_ref())
        .is_some_and(|(a, b)| {
            a.protocol == b.protocol
                && a.endpoint.port == b.endpoint.port
                && a.endpoint.host.eq_ignore_ascii_case(&b.endpoint.host)
                && a.database == b.database
                && a.username
                    .as_ref()
                    .is_none_or(|username| b.username.as_ref() == Some(username))
        })
}

fn scope_contains(declared: &NativeFieldClaim, contextual: &NativeFieldClaim) -> bool {
    match declared.slot {
        NativeOwnedSlot::SqlField(_) => {
            if !contextual
                .selector
                .sql
                .as_ref()
                .is_some_and(|sql| sql.contains("{{table}}"))
            {
                return true;
            }
            let outer = &declared.selector;
            let inner = &contextual.selector;
            let Ok(matcher) = crate::config::mysql_tables::TableMatcher::new(
                &outer.tables,
                &outer.table_patterns,
                outer.table_series.as_ref(),
            ) else {
                return false;
            };
            inner.tables.iter().all(|table| matcher.matches(table))
                && inner.table_series.as_ref().is_none_or(|series| {
                    (series.start..=series.end).all(|value| {
                        matcher.matches(&format!(
                            "{}{:0width$}",
                            series.prefix,
                            value,
                            width = series.width
                        ))
                    })
                })
                && inner.table_patterns.iter().all(|pattern| {
                    outer
                        .table_patterns
                        .iter()
                        .any(|outer| pattern_contains(outer, pattern))
                })
        }
        NativeOwnedSlot::RedisValue(_) => {
            let (Some(outer), Some(inner)) = (&declared.selector.key, &contextual.selector.key)
            else {
                return false;
            };
            key_contains(outer, inner)
                && declared.hash_field.as_ref().is_none_or(|outer| {
                    contextual
                        .hash_field
                        .as_ref()
                        .is_some_and(|inner| key_selector_contains(outer, inner))
                })
        }
        _ => false,
    }
}

fn pattern_contains(outer: &str, inner: &str) -> bool {
    outer
        .split_once('*')
        .zip(inner.split_once('*'))
        .is_some_and(|((op, os), (ip, is))| ip.starts_with(op) && is.ends_with(os))
}

fn key_contains(outer: &NativeKeySelector, inner: &NativeKeySelector) -> bool {
    match inner {
        NativeKeySelector::Exact { value } => native_key_matches(outer, value),
        NativeKeySelector::Affix { prefix, suffix }
        | NativeKeySelector::Numeric { prefix, suffix } => match outer {
            NativeKeySelector::Exact { .. } => false,
            NativeKeySelector::Affix {
                prefix: op,
                suffix: os,
            } => prefix.starts_with(op) && suffix.ends_with(os),
            NativeKeySelector::Numeric {
                prefix: op,
                suffix: os,
            } => matches!(inner, NativeKeySelector::Numeric { .. }) && prefix == op && suffix == os,
        },
    }
}

fn native_key_matches(selector: &NativeKeySelector, value: &str) -> bool {
    match selector {
        NativeKeySelector::Exact { value: exact } => value == exact,
        NativeKeySelector::Affix { prefix, suffix } => {
            value.starts_with(prefix) && value.ends_with(suffix)
        }
        NativeKeySelector::Numeric { prefix, suffix } => value
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(suffix))
            .is_some_and(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())),
    }
}

fn key_selector_contains(
    outer: &crate::policy::KeySelector,
    inner: &crate::policy::KeySelector,
) -> bool {
    if let Some(exact) = &inner.exact {
        return outer.matches(exact.as_bytes());
    }
    outer.exact.is_none()
        && outer.prefix.as_ref().is_none_or(|prefix| {
            inner
                .prefix
                .as_ref()
                .is_some_and(|inner| inner.starts_with(prefix))
        })
        && outer.suffix.as_ref().is_none_or(|suffix| {
            inner
                .suffix
                .as_ref()
                .is_some_and(|inner| inner.ends_with(suffix))
        })
        && (!outer.numeric
            || inner.numeric && outer.prefix == inner.prefix && outer.suffix == inner.suffix)
}
