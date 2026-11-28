//! Author key-local Redis scalar formats and native command contracts.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};

use crate::native::{NativeKeySelector, Proven, RedisSequenceEffect};
use crate::{GlobalField, NativeEffect, NativeMatch, NativeRule, PolicyRule, Proof, Resource};

pub mod commands;
pub mod key_format;

pub const ID_PREFIX: &str = "redis.key.";

#[derive(Debug)]
pub struct Entry {
    pub scalar: Option<GlobalField>,
    key_identity: Option<GlobalField>,
    commands: Option<CommandContract>,
    pub proof: Option<Proof>,
    declared_state: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FiniteState {
    set: SetTransition,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetTransition {
    Transition,
}

#[derive(Debug)]
struct CommandContract {
    key_format: Option<key_format::KeyFormat>,
    declarations: commands::Commands,
}

impl CommandContract {
    fn effect(
        &self,
        pattern: &str,
        proof: Option<&Proof>,
        context: &crate::AuthoringContext<'_>,
    ) -> Result<NativeEffect> {
        Ok(NativeEffect::RedisSequence(RedisSequenceEffect {
            key: self
                .key_format
                .as_ref()
                .map(|format| {
                    Ok::<_, anyhow::Error>(Proven {
                        contract: format.lower(pattern)?,
                        proof: proof.cloned(),
                    })
                })
                .transpose()?,
            commands: self.declarations.compile(proof, context)?,
        }))
    }
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields: BTreeMap<String, Value> = crate::strict_map::unique_map(deserializer)?;
        let result = (|| -> Result<Self> {
            let proof = fields
                .remove("proof")
                .map(serde_yaml::from_value)
                .transpose()?;
            let state = fields
                .remove("state")
                .map(serde_yaml::from_value::<FiniteState>)
                .transpose()?;
            let declared_state = matches!(
                state,
                Some(FiniteState {
                    set: SetTransition::Transition
                })
            );
            let key_format = fields.remove("key_format");
            let declarations = fields
                .remove("commands")
                .map(serde_yaml::from_value::<commands::Commands>)
                .transpose()?;
            let (commands, key_identity) = if let Some(declarations) = declarations {
                let key_format = key_format.map(serde_yaml::from_value).transpose()?;
                (
                    Some(CommandContract {
                        key_format,
                        declarations,
                    }),
                    None,
                )
            } else {
                let identity = key_format
                    .map(serde_yaml::from_value::<GlobalField>)
                    .transpose()
                    .context("standalone Redis key_format requires an identity format")?;
                ensure!(
                    matches!(identity, None | Some(GlobalField::Identity { .. })),
                    "standalone Redis key_format requires an identity format"
                );
                (None, identity)
            };
            let scalar = if fields.is_empty() {
                None
            } else {
                Some(serde_yaml::from_value::<GlobalField>(
                    serde_yaml::to_value(fields)?,
                )?)
            };
            ensure!(
                scalar.is_some() || key_identity.is_some() || commands.is_some() || declared_state,
                "Redis key declaration is empty"
            );
            ensure!(
                proof.is_none() || commands.is_some(),
                "Redis scalar declarations do not accept behavior proof"
            );
            Ok(Self {
                scalar,
                key_identity,
                commands,
                proof,
                declared_state,
            })
        })();
        result.map_err(serde::de::Error::custom)
    }
}

/// Validate Source proof before lowering command contracts and finite SET declarations.
pub fn require_source_proofs(policy: &Value, revision: Option<&str>) -> Result<()> {
    let Some(keys) = policy
        .get("redis")
        .and_then(|redis| redis.get("keys"))
        .and_then(Value::as_mapping)
    else {
        return Ok(());
    };
    for (pattern, raw) in keys {
        let mut declaration = raw.clone();
        let proof = declaration
            .as_mapping_mut()
            .and_then(|entry| entry.remove("proof"));
        let entry: Entry = serde_yaml::from_value(declaration)
            .with_context(|| format!("invalid Redis key {pattern:?} declaration"))?;
        if entry.declared_state || entry.commands.is_some() {
            let mut local = Mapping::new();
            if let Some(proof) = proof {
                local.insert("proof".into(), proof);
            }
            super::require_source_proof(&mut local.into(), revision).with_context(|| {
                format!("Redis key {pattern:?} behavior requires local Source proof")
            })?;
        }
    }
    Ok(())
}

pub fn selector(pattern: &str) -> Result<NativeKeySelector> {
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
    commands: &CommandContract,
    proof: Option<Proof>,
    context: &crate::AuthoringContext<'_>,
) -> Result<NativeRule> {
    let semantic_effect = commands.effect(pattern, None, context)?;
    let digest = Sha256::digest(serde_json::to_vec(&(
        &resource,
        pattern,
        "commands",
        semantic_effect,
    ))?);
    let effect = commands.effect(pattern, proof.as_ref(), context)?;
    Ok(NativeRule {
        id: format!("{ID_PREFIX}commands.{digest:x}"),
        selector: NativeMatch {
            resource,
            key: Some(selector(pattern)?),
            ..Default::default()
        },
        effect,
        proof,
        when: None,
    })
}

pub fn expand(
    entries: BTreeMap<String, Entry>,
    context: &crate::AuthoringContext<'_>,
) -> Result<(crate::RedisPolicy, Vec<Value>)> {
    ensure!(entries.len() <= 4096, "redis.keys exceeds 4096 entries");
    let mut policy = crate::RedisPolicy::default();
    let mut rules = Vec::new();
    for (pattern, entry) in entries {
        if let Some(commands) = entry.commands {
            rules.push(serde_yaml::to_value(lower(
                &pattern,
                None,
                &commands,
                entry.proof,
                context,
            )?)?);
        }
        if let Some(field) = entry.scalar {
            policy.keys.insert(pattern.clone(), field);
        }
        if let Some(identity) = entry.key_identity {
            policy.key_identities.insert(pattern, identity);
        }
    }
    Ok((policy, rules))
}

pub fn compact_settings(policy: &crate::RedisPolicy) -> Result<Value> {
    let mut keys = Mapping::new();
    for (pattern, field) in &policy.keys {
        keys.insert(pattern.as_str().into(), serde_yaml::to_value(field)?);
    }
    for (pattern, identity) in &policy.key_identities {
        key_entry(&mut keys, pattern)?.insert("key_format".into(), serde_yaml::to_value(identity)?);
    }
    Ok(Value::Mapping(Mapping::from_iter([(
        "keys".into(),
        Value::Mapping(keys),
    )])))
}

fn key_entry<'a>(keys: &'a mut Mapping, pattern: &str) -> Result<&'a mut Mapping> {
    keys.entry(pattern.into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .context("Redis key declaration requires a mapping")
}

pub fn generated(rule: &PolicyRule) -> bool {
    rule.id().starts_with(ID_PREFIX)
}

/// Only the exact generated shape folds back; arbitrary native rules retain
/// their declared selector, conditions and Source-proof boundary.
pub fn compact(
    rule: &PolicyRule,
    root: &mut Mapping,
    context: &crate::AuthoringContext<'_>,
) -> Result<bool> {
    let Some(native) = rule.as_native().filter(|_| generated(rule)) else {
        return Ok(false);
    };
    if native.selector.resource.is_some() {
        return Ok(false);
    }
    let pattern = match &native.selector.key {
        Some(NativeKeySelector::Exact { value }) => value.clone(),
        Some(NativeKeySelector::Affix { prefix, suffix }) => format!("{prefix}*{suffix}"),
        _ => return Ok(false),
    };
    let NativeEffect::RedisSequence(effect) = &native.effect else {
        return Ok(false);
    };
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
    let commands = CommandContract {
        key_format,
        declarations,
    };
    let mut semantic = native.clone();
    semantic.proof = None;
    semantic.effect = commands.effect(&pattern, None, context)?;
    if semantic != lower(&pattern, None, &commands, None, context)? {
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
    let entry = key_entry(keys, &pattern)?;
    if let Some(format) = &commands.key_format {
        ensure!(
            entry
                .insert("key_format".into(), serde_yaml::to_value(format)?)
                .is_none(),
            "duplicate Redis key format owner"
        );
    }
    ensure!(
        entry
            .insert(
                "commands".into(),
                serde_yaml::to_value(commands.declarations)?
            )
            .is_none(),
        "duplicate Redis key behavior owner"
    );
    Ok(true)
}
