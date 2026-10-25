//! Resolve explicit clock relationships on immutable JSON positions or identities.
use super::*;
use crate::policy::ClockScope;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ScopeKey {
    #[default]
    Shared,
    ArrayElement(String),
    Entity([u8; 32]),
}

impl ScopeKey {
    pub(super) fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }
}

pub(super) fn resolve(
    comparator: &Comparator<'_>,
    field: &Field<'_>,
    source_pointer: &str,
    target_pointer: &str,
    decisions: &mut Decisions,
) -> Result<ScopeKey, Difference> {
    let Some(time) = field.contract.unconditional().time() else {
        unreachable!()
    };
    match &time.clock_scope {
        ClockScope::Shared => {
            let implicit = time.clock_group.as_deref().is_some_and(|group| {
                crate::policy::is_schema_clock_group(
                    group.split(".occurrence.").next().unwrap_or(group),
                )
            });
            if implicit && field.pointer.split('/').any(|part| part == "*") {
                // A declaration describes each selected physical value. Only an
                // authored group can relate separate wildcard occurrences.
                Ok(ScopeKey::ArrayElement(source_pointer.to_owned()))
            } else {
                Ok(ScopeKey::Shared)
            }
        }
        ClockScope::ArrayElement => {
            let mut source = comparator.source_root;
            let mut target = comparator.target_root;
            let mut path = String::new();
            let mut element = None;
            for ((pattern, a), b) in field
                .pointer
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
            let source_key = time
                .clock_scope
                .peer_pointer(source_pointer)
                .ok_or_else(|| difference(source_pointer, "clock scope has no identity sibling"))?;
            let target_key = time
                .clock_scope
                .peer_pointer(target_pointer)
                .ok_or_else(|| difference(target_pointer, "clock scope has no identity sibling"))?;
            let identity = comparator.fields.iter().find(|candidate| {
                pointer_matches(candidate.pointer, &source_key, comparator.source_root)
                    && matches!(candidate.contract.unconditional(), FieldContract::Identity { .. })
            }).ok_or_else(|| difference(source_pointer, "entity clock_scope requires its explicit identity field in the selected JSON contracts"))?;
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
            let FieldContract::Identity { prefix, format, .. } = identity.contract.unconditional()
            else {
                unreachable!()
            };
            let source = comparator.source_root.pointer(&source_key).ok_or_else(|| {
                difference(source_pointer, "clock scope Source identity is absent")
            })?;
            let target = comparator.target_root.pointer(&target_key).ok_or_else(|| {
                difference(target_pointer, "clock scope Target identity is absent")
            })?;
            identity::compare(source, target, prefix, *format, &source_key, decisions)?;
            Ok(ScopeKey::Entity(identity::fingerprint(
                source,
                prefix,
                *format,
                &source_key,
            )?))
        }
    }
}
