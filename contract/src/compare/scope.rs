//! Resolve explicit clock relationships on immutable JSON positions or identities.
use super::*;
use crate::rule::ClockScope;
#[cfg(test)]
mod tests;

pub use traffic_policy::ScopeKey;

pub(super) fn resolve(
    comparator: &mut Comparator<'_>,
    pattern: &str,
    scope: &ClockScope,
    source_pointer: &str,
    target_pointer: &str,
    decisions: &mut Decisions,
) -> Result<ScopeKey, Difference> {
    match scope {
        ClockScope::Shared => Ok(ScopeKey::Shared),
        ClockScope::ArrayElement => {
            let mut source = comparator.source_root;
            let mut target = comparator.target_root;
            let mut path = String::new();
            let mut element = None;
            for ((pattern, a), b) in pattern
                .split('/')
                .skip(1)
                .zip(source_pointer.split('/').skip(1))
                .zip(target_pointer.split('/').skip(1))
            {
                path.push('/');
                path.push_str(a);
                if pattern == "*" {
                    if !source.is_array() || !target.is_array() {
                        return Err(difference(
                            source_pointer,
                            "array_element clock_scope requires actual arrays",
                        ));
                    }
                    element = Some(path.clone());
                }
                source = source.pointer(&format!("/{a}")).ok_or_else(|| {
                    difference(source_pointer, "clock scope Source field is absent")
                })?;
                target = target.pointer(&format!("/{b}")).ok_or_else(|| {
                    difference(target_pointer, "clock scope Target field is absent")
                })?;
            }
            element.map(ScopeKey::ArrayElement).ok_or_else(|| {
                difference(
                    source_pointer,
                    "array_element clock_scope requires a wildcard",
                )
            })
        }
        ClockScope::Entity { .. } => {
            let source_key = scope
                .peer_pointer(source_pointer)
                .ok_or_else(|| difference(source_pointer, "clock scope has no identity sibling"))?;
            let target_key = scope
                .peer_pointer(target_pointer)
                .ok_or_else(|| difference(target_pointer, "clock scope has no identity sibling"))?;
            let source_root = comparator.source_root;
            let target_root = comparator.target_root;
            let source = source_root
                .pointer(&source_key)
                .ok_or_else(|| difference(source_pointer, "entity scope Source value is absent"))?;
            let target = target_root
                .pointer(&target_key)
                .ok_or_else(|| difference(target_pointer, "entity scope Target value is absent"))?;
            let logical_source = match comparator.logical_roots {
                Some((root, _)) => root.pointer(&source_key).cloned().ok_or_else(|| {
                    difference(source_pointer, "entity scope logical value is absent")
                })?,
                None => serde_json::from_value(source.clone())
                    .map_err(|error| difference(source_pointer, &error.to_string()))?,
            };
            let mut selected = None;
            for candidate in comparator.fields {
                if !pointer_matches(candidate.pointer, &source_key, source_root) {
                    continue;
                }
                let Some(definition) = candidate
                    .contract
                    .unconditional()
                    .registered_definition(false)
                else {
                    continue;
                };
                let policy = comparator
                    .rule_metadata
                    .policies()
                    .prepare_definition(&definition)
                    .map_err(|error| difference(source_pointer, &error.to_string()))?;
                if let Some(key) = policy
                    .entity_key(&logical_source)
                    .map_err(|error| difference(source_pointer, &error.to_string()))?
                {
                    selected = Some((*candidate, definition, key));
                    break;
                }
            }
            let (identity, definition, key) = selected.ok_or_else(|| {
                difference(
                    source_pointer,
                    "entity clock_scope requires a selected field policy with an entity key",
                )
            })?;
            if let FieldContract::Conditional { when, .. } = identity.contract
                && !when
                    .matches_pair(
                        comparator.source_root,
                        comparator.target_root,
                        &source_key,
                        &target_key,
                    )
                    .map_err(|_| {
                        difference(source_pointer, "clock scope identity condition is invalid")
                    })?
            {
                return Err(difference(
                    source_pointer,
                    "clock scope identity contract is inactive",
                ));
            }
            comparator.registered_policy(
                &definition,
                &identity,
                source,
                target,
                &source_key,
                &target_key,
                decisions,
                0,
            )?;
            Ok(ScopeKey::Entity(key))
        }
    }
}
