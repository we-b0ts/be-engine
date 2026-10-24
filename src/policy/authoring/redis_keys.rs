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
    Database, GlobalField, NativeEffect, NativeMatch, NativeRule, PolicyRule, Proof, Protocol,
    Resource, ResourceDeclaration,
};

mod stateful;

const ID_PREFIX: &str = "redis.key.";

#[derive(Debug)]
pub(super) struct Entry {
    scalar: Option<GlobalField>,
    resource: Option<String>,
    behaviors: Vec<Behavior>,
    proof: Option<Proof>,
}

#[derive(Debug, Clone)]
enum Behavior {
    Append,
    ReadCommutation,
    ExpiryRefresh,
    ReadBack,
    FiniteSharing(stateful::Sharing),
}

impl Behavior {
    fn name(&self) -> &'static str {
        match self {
            Self::Append => "append_stream",
            Self::ReadCommutation => "read_commutation",
            Self::ExpiryRefresh => "expiry_refresh",
            Self::ReadBack => "read_back",
            Self::FiniteSharing(_) => "finite_sharing",
        }
    }
    fn operation(&self) -> &str {
        match self {
            Self::Append => "APPEND",
            Self::ReadCommutation => "GET",
            Self::ExpiryRefresh => "EXPIRE",
            Self::ReadBack => "SET",
            Self::FiniteSharing(value) => &value.operation,
        }
    }
    fn effect(&self, resource: &Resource, proof: Option<&Proof>) -> Result<NativeEffect> {
        Ok(match self {
            Self::Append => NativeEffect::RedisAppendStream,
            Self::ReadCommutation => {
                NativeEffect::RedisReadCommutation(RedisReadCommutationEffect {})
            }
            Self::ExpiryRefresh => NativeEffect::RedisExpiryRefresh(RedisExpiryRefreshEffect {}),
            Self::ReadBack => stateful::lower_read_back(resource, proof),
            Self::FiniteSharing(value) => stateful::lower_sharing(value)?.1,
        })
    }
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields: BTreeMap<String, Value> =
            crate::policy::strict_map::unique_map(deserializer)?;
        let result = (|| -> Result<Self> {
            let resource = fields
                .remove("resource")
                .map(serde_yaml::from_value)
                .transpose()?;
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
            if let Some(value) = fields.remove("finite_sharing") {
                let mut sharing = serde_yaml::from_value::<stateful::Sharing>(value)?;
                sharing.operation = stateful::lower_sharing(&sharing)?.0;
                behaviors.push(Behavior::FiniteSharing(sharing));
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
                resource.is_none() || !behaviors.is_empty(),
                "Redis resource selects key behavior; scalar formats use the global key namespace"
            );
            ensure!(
                behaviors.is_empty() || resource.is_some(),
                "Redis key behavior requires a named resource"
            );
            ensure!(
                proof.is_none() || !behaviors.is_empty(),
                "Redis scalar declarations do not accept behavior proof"
            );
            Ok(Self {
                scalar,
                resource,
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
    resource: Resource,
    behavior: &Behavior,
    proof: Option<Proof>,
) -> Result<NativeRule> {
    let semantic_effect = behavior.effect(&resource, None)?;
    let digest = Sha256::digest(serde_json::to_vec(&(
        &resource,
        pattern,
        behavior.name(),
        semantic_effect,
    ))?);
    let effect = behavior.effect(&resource, proof.as_ref())?;
    Ok(NativeRule {
        id: format!("{ID_PREFIX}{}.{digest:x}", behavior.name()),
        selector: NativeMatch {
            resource: Some(resource),
            operation: Some(behavior.operation().into()),
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
    database: Option<i64>,
    resources: &BTreeMap<String, ResourceDeclaration>,
) -> Result<(BTreeMap<String, GlobalField>, Vec<Value>)> {
    ensure!(entries.len() <= 4096, "redis.keys exceeds 4096 entries");
    let mut scalars = BTreeMap::new();
    let mut rules = Vec::new();
    for (pattern, entry) in entries {
        if !entry.behaviors.is_empty() {
            let name = entry
                .resource
                .as_ref()
                .expect("validated behavior resource");
            let mut resource = resources
                .get(name)
                .with_context(|| format!("unknown Redis key resource {name:?}"))?
                .resource
                .clone();
            ensure!(
                resource.protocol == Protocol::Redis,
                "Redis key behavior requires a Redis resource"
            );
            if resource.database.is_none() {
                resource.database = database.map(Database::Index);
            }
            ensure!(
                matches!(resource.database, Some(Database::Index(0..))),
                "Redis key behavior requires an explicit numeric database"
            );
            if entry.scalar.is_some() {
                ensure!(
                    database.is_none_or(|db| resource.database == Some(Database::Index(db))),
                    "combined Redis scalar and behavior declarations must select the same database"
                );
            }
            for behavior in entry.behaviors {
                rules.push(serde_yaml::to_value(lower(
                    &pattern,
                    resource.clone(),
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
pub(super) fn compact(
    rule: &PolicyRule,
    resources: &BTreeMap<String, ResourceDeclaration>,
    root: &mut Mapping,
) -> Result<bool> {
    let Some(native) = rule.as_native().filter(|_| generated(rule)) else {
        return Ok(false);
    };
    let Some(resource) = &native.selector.resource else {
        return Ok(false);
    };
    let behavior = match &native.effect {
        NativeEffect::RedisAppendStream => Behavior::Append,
        NativeEffect::RedisReadCommutation(_) => Behavior::ReadCommutation,
        NativeEffect::RedisExpiryRefresh(_) => Behavior::ExpiryRefresh,
        effect if stateful::is_read_back(effect, resource) => Behavior::ReadBack,
        effect => {
            if let Some(sharing) = stateful::sharing(
                effect,
                native.selector.operation.as_deref().unwrap_or_default(),
            ) {
                Behavior::FiniteSharing(sharing)
            } else {
                return Ok(false);
            }
        }
    };
    let pattern = match &native.selector.key {
        Some(NativeKeySelector::Exact { value }) => value.clone(),
        Some(NativeKeySelector::Affix { prefix, suffix }) => format!("{prefix}*{suffix}"),
        _ => return Ok(false),
    };
    let mut semantic = native.clone();
    semantic.proof = None;
    semantic.effect = behavior.effect(resource, None)?;
    if semantic != lower(&pattern, resource.clone(), &behavior, None)? {
        return Ok(false);
    }
    let database = root
        .get("redis")
        .and_then(|redis| redis.get("database"))
        .and_then(Value::as_i64);
    let name = resources
        .iter()
        .find(|(_, entry)| {
            let mut candidate = entry.resource.clone();
            if candidate.database.is_none() {
                candidate.database = database.map(Database::Index);
            }
            candidate == *resource
        })
        .map(|(name, _)| name)
        .context("generated Redis key behavior lost its named resource")?;
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
    ensure!(
        entry
            .get("resource")
            .is_none_or(|prior| prior.as_str() == Some(name)),
        "one Redis key declaration cannot combine different resource scopes"
    );
    entry.insert("resource".into(), name.clone().into());
    let value = if let Behavior::FiniteSharing(sharing) = &behavior {
        serde_yaml::to_value(sharing)?
    } else {
        Value::Bool(true)
    };
    ensure!(
        entry.insert(behavior.name().into(), value).is_none(),
        "duplicate Redis key behavior owner"
    );
    Ok(true)
}

#[cfg(test)]
mod tests;
