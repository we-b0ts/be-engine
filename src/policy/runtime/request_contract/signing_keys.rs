//! Resolve immutable signing inputs for every supported request-body adapter.
use super::*;
use crate::request_rules::keys::{ResolvedSigningKey, SigningKeySource};

pub(super) fn resolve(
    rules: &[ReplayDependencyRule],
    root: impl FnOnce() -> Result<PathBuf>,
) -> Result<BTreeMap<(String, String), ResolvedSigningKey>> {
    let references = rules
        .iter()
        .flat_map(|rule| {
            sources(rule)
                .into_iter()
                .map(move |(pointer, source)| ((rule.id.clone(), pointer), source))
        })
        .collect::<Vec<_>>();
    if references.is_empty() {
        return Ok(BTreeMap::new());
    }
    let root = root()?;
    references
        .into_iter()
        .map(|(identity, source)| Ok((identity, ResolvedSigningKey::resolve(&root, &source)?)))
        .collect()
}

fn sources(rule: &ReplayDependencyRule) -> Vec<(String, SigningKeySource)> {
    let mut sources = Vec::new();
    if let Some(super::super::redis_value::RedisSelector::Requests(selector)) = &rule.redis {
        for command in &selector.commands {
            for argument in command.argument_values.values() {
                if let config::ArgumentRule::Json(json) = argument {
                    for (pointer, field) in &json.json {
                        if let config::JsonField::Jwt(field) = field {
                            sources.push((pointer.clone(), field.jwt.signing_key_source.clone()));
                        }
                    }
                }
            }
        }
    }
    sources
}
