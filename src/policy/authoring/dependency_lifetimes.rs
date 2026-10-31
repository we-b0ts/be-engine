//! Dependency lifetime declarations lower to existing sharing/process owners.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};

use super::resources;
use crate::policy::native::{
    FiniteSharingEffect, NativeKeySelector, ProcessOwnedEffect, ProcessSelector,
};
use crate::policy::{
    NativeEffect, NativeMatch, NativeRule, PolicyRule, Proof, ResourceDeclaration,
};

const PREFIX: &str = "dependency.";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Declaration {
    pub requests: Vec<Entry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessDeclaration {
    #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
    pub tasks: BTreeMap<String, Declaration>,
}

fn task_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name == name.trim()
            && name.len() <= 128
            && !name.chars().any(char::is_control),
        "process dependency task_name requires a bounded nonempty Source task name"
    );
    Ok(())
}

#[derive(Debug, Clone)]
pub(super) struct Entry {
    protocol: String,
    payload: Value,
    proof: Option<Proof>,
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields: BTreeMap<String, Value> =
            crate::policy::strict_map::unique_map(deserializer)?;
        let proof = fields
            .remove("proof")
            .map(serde_yaml::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?;
        if fields.len() != 1 {
            return Err(serde::de::Error::custom(
                "dependency request requires exactly one protocol wrapper",
            ));
        }
        let (protocol, payload) = fields.into_iter().next().expect("one protocol");
        if !matches!(
            protocol.as_str(),
            "http" | "redis" | "redis_pubsub" | "mysql" | "memcached" | "motan"
        ) || !payload.is_mapping()
        {
            return Err(serde::de::Error::custom(
                "dependency request requires one supported protocol mapping",
            ));
        }
        Ok(Self {
            protocol,
            payload,
            proof,
        })
    }
}

#[derive(Clone, Copy)]
enum Scope {
    LocalCache,
    Process,
}
impl Scope {
    fn name(self) -> &'static str {
        match self {
            Self::LocalCache => "localcache",
            Self::Process => "process_dependencies",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedisCacheRequest {
    operation: String,
    key: String,
    #[serde(default)]
    field: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpCacheRequest {
    host: String,
    method: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpProcessRequest {
    host: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    methods: Option<Vec<String>>,
    #[serde(default)]
    path_prefixes: Option<Vec<String>>,
}

fn http_host(host: &str) -> Result<String> {
    let authority: hyper::http::uri::Authority = host.parse()?;
    ensure!(
        !host.is_empty()
            && host.len() <= 253
            && !host.chars().any(char::is_whitespace)
            && !host.contains(['@', '/', '?', '#'])
            && authority.as_str().eq_ignore_ascii_case(authority.host()),
        "HTTP dependency host requires an explicit hostname without a port or URL components"
    );
    Ok(host.to_ascii_lowercase())
}

fn http_method(method: &str) -> Result<String> {
    let method = method.to_ascii_uppercase();
    hyper::Method::from_bytes(method.as_bytes())?;
    Ok(method)
}

fn http_path(path: &str) -> Result<()> {
    ensure!(
        path.starts_with('/')
            && path.len() <= 2048
            && !path.chars().any(char::is_control)
            && !path.contains(['?', '#']),
        "HTTP dependency path requires a bounded request path without query or fragment"
    );
    crate::path_pattern::validate_literal_path(path)?;
    Ok(())
}

fn http_process(payload: Value) -> Result<ProcessSelector> {
    let selected: HttpProcessRequest = serde_yaml::from_value(payload)?;
    let host = http_host(&selected.host)?;
    ensure!(
        selected.method.is_some() != selected.methods.is_some()
            && selected.path.is_some() != selected.path_prefixes.is_some(),
        "process HTTP request requires method or methods, and path or path_prefixes"
    );
    let methods = selected
        .method
        .map(|method| vec![method])
        .or(selected.methods)
        .expect("checked method");
    let methods = methods
        .iter()
        .map(|method| http_method(method))
        .collect::<Result<Vec<_>>>()?;
    let path_prefixes = selected
        .path
        .map(|path| vec![path])
        .or(selected.path_prefixes)
        .expect("checked path");
    ensure!(
        !methods.is_empty()
            && methods.len() <= 32
            && !path_prefixes.is_empty()
            && path_prefixes.len() <= 64,
        "process HTTP requests require bounded nonempty methods and path prefixes"
    );
    for path in &path_prefixes {
        http_path(path)?;
        ensure!(
            path.len() <= 1024,
            "process HTTP path prefix exceeds 1024 bytes"
        );
    }
    ensure!(
        methods.iter().collect::<BTreeSet<_>>().len() == methods.len()
            && path_prefixes.iter().collect::<BTreeSet<_>>().len() == path_prefixes.len(),
        "duplicate process HTTP method or path prefix"
    );
    Ok(ProcessSelector::Http {
        authorities: vec![host],
        methods,
        path_prefixes,
    })
}

fn local(entry: &Entry) -> Result<(NativeMatch, NativeEffect)> {
    match entry.protocol.as_str() {
        "redis" => {
            let selected: RedisCacheRequest = serde_yaml::from_value(entry.payload.clone())?;
            let operation = selected.operation.to_ascii_uppercase();
            ensure!(
                matches!(operation.as_str(), "GET" | "HGET")
                    && (operation == "HGET") == selected.field.is_some(),
                "localcache Redis requests require GET or HGET with its exact field"
            );
            ensure!(
                !selected.key.is_empty()
                    && selected.key.len() <= 1024
                    && !selected.key.chars().any(char::is_control),
                "localcache Redis key requires bounded exact bytes"
            );
            ensure!(
                selected.field.as_ref().is_none_or(|field| !field.is_empty()
                    && field.len() <= 1024
                    && !field.contains(['\r', '\n', '\0'])),
                "localcache Redis field requires bounded exact bytes"
            );
            Ok((
                NativeMatch {
                    operation: Some(operation),
                    key: Some(NativeKeySelector::Exact {
                        value: selected.key,
                    }),
                    ..Default::default()
                },
                NativeEffect::FiniteSharing(FiniteSharingEffect::Redis {
                    hash_field: selected.field,
                }),
            ))
        }
        "http" => {
            let selected: HttpCacheRequest = serde_yaml::from_value(entry.payload.clone())?;
            let host = http_host(&selected.host)?;
            let method = http_method(&selected.method)?;
            http_path(&selected.path)?;
            Ok((
                NativeMatch {
                    http_host: Some(host),
                    operation: Some(method),
                    path: Some(selected.path),
                    ..Default::default()
                },
                NativeEffect::FiniteSharing(FiniteSharingEffect::Http),
            ))
        }
        _ => anyhow::bail!("localcache requests currently support HTTP and Redis"),
    }
}

fn process(
    entry: &Entry,
    task: &str,
    revision: Option<&str>,
    named: &BTreeMap<String, ResourceDeclaration>,
) -> Result<NativeEffect> {
    task_name(task)?;
    let revision = revision.context("process_dependencies requires the root source_revision")?;
    super::proof::revision(revision)?;
    let payload = if entry.protocol == "http" {
        let selector = http_process(entry.payload.clone())?;
        let mut payload = serde_yaml::to_value(selector)?;
        payload
            .as_mapping_mut()
            .expect("HTTP selector")
            .remove("protocol");
        payload
    } else {
        entry.payload.clone()
    };
    let mut selector = payload
        .as_mapping()
        .context("process selector requires a mapping")?
        .clone();
    ensure!(
        !selector.contains_key("protocol"),
        "process request protocol belongs in its wrapper"
    );
    selector.insert("protocol".into(), entry.protocol.clone().into());
    // Only the existing schema-owned MySQL selector/member resource positions
    // are expanded. SQL, argument strings and business values are not traversed.
    let mut owned: Value = serde_yaml::from_str("effect: {kind: process_owned}")?;
    owned["effect"]["selector"] = selector.into();
    resources::expand(&mut owned, named)?;
    if let Some(proof) = &entry.proof {
        owned["proof"] = serde_yaml::to_value(proof)?;
    }
    super::walk::expand_rule(&mut owned, Some(revision))?;
    let selector: ProcessSelector = serde_yaml::from_value(owned["effect"]["selector"].clone())?;
    Ok(NativeEffect::ProcessOwned(ProcessOwnedEffect {
        source_revision: revision.into(),
        task_name: Some(task.into()),
        selector,
        origin: None,
    }))
}

fn without_proofs(mut rule: NativeRule) -> NativeRule {
    rule.proof = None;
    if let NativeEffect::ProcessOwned(effect) = &mut rule.effect {
        match &mut effect.selector {
            ProcessSelector::Mysql {
                transaction_members,
                ..
            } => {
                for member in transaction_members {
                    member.proof = None;
                }
            }
            ProcessSelector::Redis {
                script: Some(script),
                ..
            } => script.proof = None,
            _ => {}
        }
    }
    rule
}

fn lower(
    scope: Scope,
    entry: &Entry,
    task: Option<&str>,
    revision: Option<&str>,
    named: &BTreeMap<String, ResourceDeclaration>,
) -> Result<NativeRule> {
    let (selector, effect) = match scope {
        Scope::LocalCache => local(entry)?,
        Scope::Process => (
            NativeMatch::default(),
            process(
                entry,
                task.context("process request requires its Source task_name")?,
                revision,
                named,
            )?,
        ),
    };
    let mut rule = NativeRule {
        id: String::new(),
        selector,
        effect,
        proof: entry.proof.clone(),
        when: None,
    };
    let mut semantic = without_proofs(rule.clone());
    // Source provenance still participates in policy validation/fingerprints,
    // but changing the snapshot does not change this request's identity.
    if let NativeEffect::ProcessOwned(effect) = &mut semantic.effect {
        effect.source_revision.clear();
    }
    let hash = Sha256::digest(serde_json::to_vec(&(
        scope.name(),
        semantic.selector,
        semantic.effect,
    ))?);
    rule.id = format!("{PREFIX}{}.{hash:x}", scope.name());
    Ok(rule)
}

pub(super) fn expand(
    localcache: Option<Declaration>,
    process_dependencies: Option<ProcessDeclaration>,
    revision: Option<&str>,
    named: &BTreeMap<String, ResourceDeclaration>,
) -> Result<Vec<Value>> {
    let mut generated = BTreeSet::new();
    let mut rules = Vec::new();
    let mut append = |scope, task: Option<&str>, declaration: Declaration| -> Result<()> {
        ensure!(
            declaration.requests.len() <= 4096,
            "dependency lifetime requests exceed 4096 entries"
        );
        for entry in declaration.requests {
            let rule = lower(scope, &entry, task, revision, named)?;
            ensure!(
                generated.insert(rule.id.clone()),
                "duplicate dependency lifetime request"
            );
            ensure!(
                rules.len() < 4096,
                "dependency lifetime declarations exceed 4096 requests"
            );
            rules.push(serde_yaml::to_value(rule)?);
        }
        Ok(())
    };
    if let Some(declaration) = localcache {
        append(Scope::LocalCache, None, declaration)?;
    }
    if let Some(declaration) = process_dependencies {
        ensure!(
            declaration.tasks.len() <= 256,
            "process dependencies exceed 256 Source tasks"
        );
        for (task, declaration) in declaration.tasks {
            task_name(&task)?;
            append(Scope::Process, Some(&task), declaration)?;
        }
    }
    Ok(rules)
}

pub(super) fn generated(rule: &PolicyRule) -> bool {
    ["dependency.localcache.", "dependency.process_dependencies."]
        .iter()
        .any(|prefix| rule.id().starts_with(prefix))
}

fn entry_from_rule(
    rule: &NativeRule,
    named: &BTreeMap<String, ResourceDeclaration>,
) -> Result<Option<(Scope, Option<String>, Entry)>> {
    let (scope, task, protocol, payload) = match &rule.effect {
        NativeEffect::FiniteSharing(FiniteSharingEffect::Http) => {
            let (Some(host), Some(method), Some(path)) = (
                &rule.selector.http_host,
                &rule.selector.operation,
                &rule.selector.path,
            ) else {
                return Ok(None);
            };
            let mut selected = Mapping::new();
            selected.insert("host".into(), host.clone().into());
            selected.insert("method".into(), method.clone().into());
            selected.insert("path".into(), path.clone().into());
            (
                Scope::LocalCache,
                None,
                "http".to_owned(),
                Value::Mapping(selected),
            )
        }
        NativeEffect::FiniteSharing(FiniteSharingEffect::Redis { hash_field }) => {
            let (Some(operation), Some(NativeKeySelector::Exact { value })) =
                (&rule.selector.operation, &rule.selector.key)
            else {
                return Ok(None);
            };
            let mut selected = Mapping::new();
            selected.insert("operation".into(), operation.clone().into());
            selected.insert("key".into(), value.clone().into());
            if let Some(field) = hash_field {
                selected.insert("field".into(), field.clone().into());
            }
            (
                Scope::LocalCache,
                None,
                "redis".to_owned(),
                Value::Mapping(selected),
            )
        }
        NativeEffect::ProcessOwned(effect) if effect.origin.is_none() => {
            let Some(task) = effect.task_name.as_ref() else {
                return Ok(None);
            };
            if task_name(task).is_err() {
                return Ok(None);
            }
            let clean = without_proofs(rule.clone());
            let mut owned = serde_yaml::to_value(clean)?;
            resources::compact(&mut owned, &resources::names(named)?)?;
            super::walk::compact_rule(&mut owned, Some(&effect.source_revision))?;
            let mut selector = owned["effect"]["selector"]
                .as_mapping()
                .context("process selector requires mapping")?
                .clone();
            let protocol = selector
                .remove("protocol")
                .and_then(|value| value.as_str().map(str::to_owned))
                .context("process protocol is missing")?;
            if protocol == "http" {
                let Some(authorities) = selector.remove("authorities") else {
                    return Ok(None);
                };
                let Some(authorities) = authorities.as_sequence().filter(|items| items.len() == 1)
                else {
                    return Ok(None);
                };
                let Some(host) = authorities[0].as_str() else {
                    return Ok(None);
                };
                if http_host(host).is_err() {
                    return Ok(None);
                }
                selector.insert("host".into(), host.into());
                for (plural, singular) in [("methods", "method"), ("path_prefixes", "path")] {
                    let Some(values) = selector.get(plural).and_then(Value::as_sequence) else {
                        return Ok(None);
                    };
                    if values.len() == 1 {
                        let value = values[0].clone();
                        selector.remove(plural);
                        selector.insert(singular.into(), value);
                    }
                }
            }
            (
                Scope::Process,
                Some(task.clone()),
                protocol,
                Value::Mapping(selector),
            )
        }
        _ => return Ok(None),
    };
    Ok(Some((
        scope,
        task,
        Entry {
            protocol,
            payload,
            proof: None,
        },
    )))
}

/// Only canonical generated shapes fold into the compact namespace. Extra
/// API/body/resource/origin constraints remain with their complete native rule.
pub(super) fn compact(
    rule: &PolicyRule,
    named: &BTreeMap<String, ResourceDeclaration>,
    root: &mut Mapping,
) -> Result<bool> {
    let Some(rule) = rule.as_native().filter(|_| generated(rule)) else {
        return Ok(false);
    };
    let Some((scope, task, entry)) = entry_from_rule(rule, named)? else {
        return Ok(false);
    };
    let revision = root.get("source_revision").and_then(Value::as_str);
    let Ok(canonical) = lower(scope, &entry, task.as_deref(), revision, named) else {
        return Ok(false);
    };
    if without_proofs(rule.clone()) != canonical {
        return Ok(false);
    }
    let declaration = root
        .entry(scope.name().into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .context("dependency lifetime declaration requires a mapping")?;
    let declaration = if let Some(task) = task {
        declaration
            .entry("tasks".into())
            .or_insert_with(|| Value::Mapping(Mapping::new()))
            .as_mapping_mut()
            .context("process dependencies tasks require a mapping")?
            .entry(task.into())
            .or_insert_with(|| Value::Mapping(Mapping::new()))
            .as_mapping_mut()
            .context("process task requires a declaration")?
    } else {
        declaration
    };
    let requests = declaration
        .entry("requests".into())
        .or_insert_with(|| Value::Sequence(vec![]))
        .as_sequence_mut()
        .context("dependency lifetime requests require a list")?;
    let mut wrapper = Mapping::new();
    wrapper.insert(entry.protocol.into(), entry.payload);
    let value = Value::Mapping(wrapper);
    ensure!(
        !requests.contains(&value),
        "duplicate dependency lifetime request"
    );
    requests.push(value);
    Ok(true)
}

#[cfg(test)]
mod tests;
