//! Key-local behavior declarations lower to the existing native effect owners.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};

use crate::policy::native::{
    NativeKeySelector, RedisExpiryRefreshEffect, RedisReadCommutationEffect,
};
use crate::policy::{
    GlobalField, NativeEffect, NativeMatch, NativeRule, PolicyRule, Proof, Resource,
};

mod commands;
mod key_format;
mod stateful;

const ID_PREFIX: &str = "redis.key.";

#[derive(Debug)]
pub(super) struct Entry {
    scalar: Option<GlobalField>,
    behaviors: Vec<Behavior>,
    proof: Option<Proof>,
}

#[derive(Debug, Clone)]
enum Behavior {
    Append,
    ReadCommutation,
    ExpiryRefresh,
    ReadBack,
    Commands {
        key_format: Option<key_format::KeyFormat>,
        declarations: commands::Commands,
    },
}

impl Behavior {
    fn name(&self) -> &'static str {
        match self {
            Self::Append => "append_stream",
            Self::ReadCommutation => "read_commutation",
            Self::ExpiryRefresh => "expiry_refresh",
            Self::ReadBack => "read_back",
            Self::Commands { .. } => "commands",
        }
    }
    fn operation(&self) -> Option<&str> {
        match self {
            Self::Append => Some("APPEND"),
            Self::ReadCommutation => Some("GET"),
            Self::ExpiryRefresh => Some("EXPIRE"),
            Self::ReadBack => Some("SET"),
            Self::Commands { .. } => None,
        }
    }
    fn effect(
        &self,
        pattern: &str,
        resource: Option<&Resource>,
        proof: Option<&Proof>,
    ) -> Result<NativeEffect> {
        Ok(match self {
            Self::Append => NativeEffect::RedisAppendStream,
            Self::ReadCommutation => {
                NativeEffect::RedisReadCommutation(RedisReadCommutationEffect {})
            }
            Self::ExpiryRefresh => NativeEffect::RedisExpiryRefresh(RedisExpiryRefreshEffect {}),
            Self::ReadBack => stateful::lower_read_back(resource, proof),
            Self::Commands {
                key_format,
                declarations,
            } => {
                use crate::policy::native::{Proven, RedisSequenceEffect};
                NativeEffect::RedisSequence(RedisSequenceEffect {
                    key: key_format
                        .as_ref()
                        .map(|format| {
                            Ok::<_, anyhow::Error>(Proven {
                                contract: format.lower(pattern)?,
                                proof: proof.cloned(),
                            })
                        })
                        .transpose()?,
                    commands: declarations.lower(proof)?,
                    read_back: vec![],
                })
            }
        })
    }
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields: BTreeMap<String, Value> =
            crate::policy::strict_map::unique_map(deserializer)?;
        let result = (|| -> Result<Self> {
            let proof = fields
                .remove("proof")
                .map(serde_yaml::from_value)
                .transpose()?;
            let mut behaviors = Vec::new();
            for behavior in [
                Behavior::Append,
                Behavior::ReadCommutation,
                Behavior::ExpiryRefresh,
                Behavior::ReadBack,
            ] {
                if let Some(value) = fields.remove(behavior.name()) {
                    ensure!(
                        value == Value::Bool(true),
                        "Redis key {} must be true when declared",
                        behavior.name()
                    );
                    behaviors.push(behavior);
                }
            }
            let key_format = fields
                .remove("key_format")
                .map(serde_yaml::from_value::<key_format::KeyFormat>)
                .transpose()?;
            let commands = fields
                .remove("commands")
                .map(serde_yaml::from_value::<commands::Commands>)
                .transpose()?;
            ensure!(
                key_format.is_none() || commands.is_some(),
                "Redis key_format requires its command declarations"
            );
            if let Some(declarations) = commands {
                behaviors.push(Behavior::Commands {
                    key_format,
                    declarations,
                });
            }
            let scalar = if fields.is_empty() {
                None
            } else {
                Some(serde_yaml::from_value::<GlobalField>(
                    serde_yaml::to_value(fields)?,
                )?)
            };
            ensure!(
                !behaviors
                    .iter()
                    .any(|behavior| matches!(behavior, Behavior::ReadBack))
                    || scalar.as_ref().is_some_and(GlobalField::is_identity),
                "Redis read_back requires the key's identity scalar format"
            );
            ensure!(
                scalar.is_some() || !behaviors.is_empty(),
                "Redis key declaration is empty"
            );
            ensure!(
                proof.is_none() || !behaviors.is_empty(),
                "Redis scalar declarations do not accept behavior proof"
            );
            Ok(Self {
                scalar,
                behaviors,
                proof,
            })
        })();
        result.map_err(serde::de::Error::custom)
    }
}

fn selector(pattern: &str) -> Result<NativeKeySelector> {
    ensure!(
        !pattern.is_empty()
            && pattern.len() <= 1024
            && !pattern.chars().any(char::is_control)
            && pattern.bytes().filter(|&byte| byte == b'*').count() <= 1,
        "Redis behavior requires a bounded exact key or single-wildcard pattern"
    );
    Ok(match pattern.split_once('*') {
        Some((prefix, suffix)) => {
            ensure!(
                !prefix.is_empty() || !suffix.is_empty(),
                "Redis behavior cannot select every key"
            );
            NativeKeySelector::Affix {
                prefix: prefix.into(),
                suffix: suffix.into(),
            }
        }
        None => NativeKeySelector::Exact {
            value: pattern.into(),
        },
    })
}

fn lower(
    pattern: &str,
    resource: Option<Resource>,
    behavior: &Behavior,
    proof: Option<Proof>,
) -> Result<NativeRule> {
    let semantic_effect = behavior.effect(pattern, resource.as_ref(), None)?;
    let digest = Sha256::digest(serde_json::to_vec(&(
        &resource,
        pattern,
        behavior.name(),
        semantic_effect,
    ))?);
    let effect = behavior.effect(pattern, resource.as_ref(), proof.as_ref())?;
    Ok(NativeRule {
        id: format!("{ID_PREFIX}{}.{digest:x}", behavior.name()),
        selector: NativeMatch {
            resource,
            operation: behavior.operation().map(str::to_owned),
            key: Some(selector(pattern)?),
            ..Default::default()
        },
        effect,
        proof,
        when: None,
    })
}

pub(super) fn expand(
    entries: BTreeMap<String, Entry>,
) -> Result<(BTreeMap<String, GlobalField>, Vec<Value>)> {
    ensure!(entries.len() <= 4096, "redis.keys exceeds 4096 entries");
    let mut scalars = BTreeMap::new();
    let mut rules = Vec::new();
    for (pattern, entry) in entries {
        if !entry.behaviors.is_empty() {
            for behavior in entry.behaviors {
                rules.push(serde_yaml::to_value(lower(
                    &pattern,
                    None,
                    &behavior,
                    entry.proof.clone(),
                )?)?);
            }
        }
        if let Some(field) = entry.scalar {
            scalars.insert(pattern, field);
        }
    }
    Ok((scalars, rules))
}

pub(super) fn generated(rule: &PolicyRule) -> bool {
    rule.id().starts_with(ID_PREFIX)
}

/// Only the exact generated shape folds back; arbitrary native rules retain
/// their declared selector, conditions and Source-proof boundary.
pub(super) fn compact(rule: &PolicyRule, root: &mut Mapping) -> Result<bool> {
    let Some(native) = rule.as_native().filter(|_| generated(rule)) else {
        return Ok(false);
    };
    if native.selector.resource.is_some() {
        return Ok(false);
    }
    let resource = None;
    let pattern = match &native.selector.key {
        Some(NativeKeySelector::Exact { value }) => value.clone(),
        Some(NativeKeySelector::Affix { prefix, suffix }) => format!("{prefix}*{suffix}"),
        _ => return Ok(false),
    };
    let behavior = match &native.effect {
        NativeEffect::RedisAppendStream => Behavior::Append,
        NativeEffect::RedisReadCommutation(_) => Behavior::ReadCommutation,
        NativeEffect::RedisExpiryRefresh(_) => Behavior::ExpiryRefresh,
        effect if stateful::is_read_back(effect, None) => Behavior::ReadBack,
        NativeEffect::RedisSequence(effect) if effect.read_back.is_empty() => {
            let key_format = if let Some(key) = &effect.key {
                let Some(format) = key_format::reverse(&pattern, &key.contract)? else {
                    return Ok(false);
                };
                Some(format)
            } else {
                None
            };
            let Some(declarations) = commands::Commands::reverse(&effect.commands)? else {
                return Ok(false);
            };
            Behavior::Commands {
                key_format,
                declarations,
            }
        }
        _ => return Ok(false),
    };
    let mut semantic = native.clone();
    semantic.proof = None;
    semantic.effect = behavior.effect(&pattern, resource, None)?;
    if semantic != lower(&pattern, resource.cloned(), &behavior, None)? {
        return Ok(false);
    }
    let redis = root
        .entry("redis".into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .context("Redis settings require a mapping")?;
    let keys = redis
        .entry("keys".into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .context("Redis keys require a mapping")?;
    let entry = keys
        .entry(pattern.into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .context("Redis key declaration requires a mapping")?;
    let value = match &behavior {
        Behavior::Commands {
            key_format,
            declarations,
        } => {
            if let Some(format) = key_format {
                ensure!(
                    entry
                        .insert("key_format".into(), serde_yaml::to_value(format)?)
                        .is_none(),
                    "duplicate Redis key format owner"
                );
            }
            serde_yaml::to_value(declarations)?
        }
        _ => Value::Bool(true),
    };
    ensure!(
        entry.insert(behavior.name().into(), value).is_none(),
        "duplicate Redis key behavior owner"
    );
    Ok(true)
}

#[cfg(test)]
mod tests;
