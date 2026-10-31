//! Authoring documents resolve to fully explicit typed rules before compilation.
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::{Mapping, Value};

use super::{
    api, dependency_lifetimes, http, proof, recording, redis_keys, resources, signatures, walk,
};
use crate::policy::{PolicyRule, TrafficPolicy};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    #[serde(default, deserialize_with = "declared_revision")]
    source_revision: Option<String>,
    #[serde(default)]
    recording: Option<recording::Declaration>,
    #[serde(default)]
    json: Option<crate::policy::JsonPolicy>,
    #[serde(default)]
    mysql: Option<crate::policy::MysqlPolicy>,
    #[serde(default)]
    redis: Option<RedisDocument>,
    #[serde(default)]
    http: Option<http::HttpDocument>,
    #[serde(default)]
    docx: Option<api::DocxDefinition>,
    #[serde(default)]
    localcache: Option<dependency_lifetimes::Declaration>,
    #[serde(default)]
    process_dependencies: Option<dependency_lifetimes::ProcessDeclaration>,
    #[serde(default, deserialize_with = "crate::policy::strict_map::unique_map")]
    signatures: std::collections::BTreeMap<String, crate::policy::SignatureDefinition>,
    #[serde(default)]
    api: Option<api::ApiDefinitions>,
    #[serde(default, deserialize_with = "optional_async_api")]
    async_api: Option<std::collections::BTreeMap<String, crate::policy::AsyncApiRules>>,
    #[serde(default, deserialize_with = "crate::policy::strict_map::unique_map")]
    resources: std::collections::BTreeMap<String, crate::policy::ResourceDeclaration>,
    #[serde(default)]
    rules: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedisDocument {
    #[serde(default, deserialize_with = "redis_keys")]
    keys: Option<std::collections::BTreeMap<String, redis_keys::Entry>>,
    #[serde(default, deserialize_with = "redis_rules")]
    rules: Option<Vec<Value>>,
}

fn optional_async_api<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<std::collections::BTreeMap<String, crate::policy::AsyncApiRules>>, D::Error> {
    crate::policy::strict_map::unique_map(deserializer).map(Some)
}

fn redis_keys<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<std::collections::BTreeMap<String, redis_keys::Entry>>, D::Error> {
    crate::policy::strict_map::unique_map(deserializer).map(Some)
}

fn redis_rules<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<Value>>, D::Error> {
    Vec::deserialize(deserializer).map(Some)
}

fn declared_revision<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

impl<'de> Deserialize<'de> for TrafficPolicy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let document = Document::deserialize(deserializer)?;
        let result = (|| -> anyhow::Result<Self> {
            if let Some(revision) = &document.source_revision {
                proof::revision(revision)?;
            }
            resources::validate(&document.resources)?;
            crate::policy::signatures::validate(&document.signatures)?;
            let (redis, nested_rules) = redis_document(document.redis)?;
            let (http, http_rules) = http::expand(document.http, &document.resources)?;
            let mut declared_rules = document.rules;
            declared_rules.extend(recording::expand(
                document.recording,
                document.source_revision.as_deref(),
            )?);
            declared_rules.extend(nested_rules);
            declared_rules.extend(http_rules);
            declared_rules.extend(api::expand(
                document.api,
                &document.signatures,
                document.docx.as_ref(),
            )?);
            declared_rules.extend(dependency_lifetimes::expand(
                document.localcache,
                document.process_dependencies,
                document.source_revision.as_deref(),
                &document.resources,
            )?);
            let mut rules = Vec::with_capacity(declared_rules.len());
            for mut rule in declared_rules {
                let id = rule
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("<missing-id>")
                    .to_owned();
                resources::expand(&mut rule, &document.resources)?;
                walk::expand_rule(&mut rule, document.source_revision.as_deref())
                    .map_err(|error| anyhow::anyhow!("rule {id:?}: {error:#}"))?;
                rules.push(serde_yaml::from_value(rule)?);
            }
            sort_rules(&mut rules);
            Ok(Self {
                format: document.format,
                source_revision: document.source_revision,
                json: document.json,
                mysql: document.mysql,
                redis,
                http,
                async_api: document.async_api,
                signatures: document.signatures,
                resources: document.resources,
                rules,
            })
        })();
        result.map_err(serde::de::Error::custom)
    }
}

fn redis_document(
    value: Option<RedisDocument>,
) -> Result<(Option<crate::policy::RedisPolicy>, Vec<Value>)> {
    let Some(value) = value else {
        return Ok((None, vec![]));
    };
    let has_settings = value.keys.is_some();
    let (keys, generated) = redis_keys::expand(value.keys.unwrap_or_default())?;
    let policy = if !has_settings && value.rules.is_some() {
        None
    } else {
        Some(crate::policy::RedisPolicy { keys })
    };
    let mut rules = value.rules.unwrap_or_default();
    rules.extend(generated);
    Ok((policy, rules))
}

fn sort_rules(rules: &mut [PolicyRule]) {
    rules.sort_by_key(|rule| {
        // Recorder response plugins use first-match precedence. Keep this
        // family in its authored order rather than sorting generated IDs.
        if capture_response(rule) {
            return (true, false, false, String::new());
        }
        (
            false,
            redis_rule(rule),
            redis_keys::generated(rule)
                || dependency_lifetimes::generated(rule)
                || signatures::generated(rule)
                || api::generated(rule)
                || http::generated(rule),
            if redis_keys::generated(rule)
                || dependency_lifetimes::generated(rule)
                || signatures::generated(rule)
                || api::generated(rule)
                || http::generated(rule)
            {
                rule.id().to_owned()
            } else {
                String::new()
            },
        )
    });
}

fn capture_response(rule: &PolicyRule) -> bool {
    matches!(rule, PolicyRule::Native(rule)
        if matches!(rule.effect, crate::policy::NativeEffect::CaptureHttpResponse(_)))
}

fn compact_capture_suffix(document: &TrafficPolicy) -> std::collections::BTreeSet<String> {
    let mut selected = std::collections::BTreeSet::new();
    let mut probe = Mapping::new();
    // Parsing appends HTTP response rewrites after native rules. Only a representable
    // suffix can move there without changing capture/plugin precedence.
    for rule in document
        .rules
        .iter()
        .rev()
        .filter(|rule| capture_response(rule))
    {
        if !matches!(
            http::compact(rule, &document.resources, &mut probe),
            Ok(true)
        ) {
            break;
        }
        selected.insert(rule.id().to_owned());
    }
    selected
}

fn redis_rule(rule: &PolicyRule) -> bool {
    let PolicyRule::Native(rule) = rule else {
        return false;
    };
    rule.selector
        .resource
        .as_ref()
        .is_some_and(|resource| resource.protocol == crate::policy::Protocol::Redis)
        || matches!(
            rule.effect,
            crate::policy::NativeEffect::RedisSequence(_)
                | crate::policy::NativeEffect::RedisAppendStream
                | crate::policy::NativeEffect::RedisReadCommutation(_)
                | crate::policy::NativeEffect::RedisReadObservation
                | crate::policy::NativeEffect::RedisExpiryRefresh(_)
                | crate::policy::NativeEffect::RedisActivityRefresh(_)
        )
        || matches!(&rule.effect, crate::policy::NativeEffect::ProcessOwned(effect)
            if matches!(effect.selector, crate::policy::native::ProcessSelector::Redis { .. }))
}

/// Typed callers can insert rules without a document context; normalize them
/// here too so compile, rendering and plan evidence bind the same Source.
pub(crate) fn expanded(document: &TrafficPolicy) -> Result<TrafficPolicy> {
    resources::validate(&document.resources)?;
    if let Some(revision) = &document.source_revision {
        proof::revision(revision)?;
    }
    let mut rules = document
        .rules
        .iter()
        .map(|rule| {
            if matches!(rule, PolicyRule::Value(_)) {
                // Value rules are internal comparator IR, never an authored
                // configuration or a legacy document compatibility path.
                return Ok(rule.clone());
            }
            let mut value = serde_yaml::to_value(rule)?;
            walk::expand_rule(&mut value, document.source_revision.as_deref())?;
            serde_yaml::from_value(value).map_err(Into::into)
        })
        .collect::<Result<Vec<PolicyRule>>>()?;
    sort_rules(&mut rules);
    Ok(TrafficPolicy {
        format: document.format.clone(),
        source_revision: document.source_revision.clone(),
        json: document.json.clone(),
        mysql: document.mysql.clone(),
        redis: document.redis.clone(),
        http: document.http.clone(),
        async_api: document.async_api.clone(),
        signatures: document.signatures.clone(),
        resources: document.resources.clone(),
        rules,
    })
}

pub fn effective_rules(document: &TrafficPolicy) -> Result<Vec<PolicyRule>> {
    Ok(expanded(document)?.rules)
}

impl Serialize for TrafficPolicy {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        compact_value(self)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

pub(super) fn compact_value(document: &TrafficPolicy) -> Result<Value> {
    let document = expanded(document)?;
    ensure!(
        document.format == crate::policy::POLICY_FORMAT,
        "policy format must be traffic-policy/v3"
    );
    let mut root = Mapping::new();
    root.insert("format".into(), document.format.clone().into());
    if let Some(revision) = &document.source_revision {
        root.insert("source_revision".into(), revision.clone().into());
    }
    if let Some(json) = &document.json {
        root.insert("json".into(), serde_yaml::to_value(json)?);
    }
    if let Some(mysql) = &document.mysql {
        root.insert("mysql".into(), serde_yaml::to_value(mysql)?);
    }
    if let Some(redis) = &document.redis {
        root.insert("redis".into(), serde_yaml::to_value(redis)?);
    }
    if let Some(http) = &document.http {
        root.insert("http".into(), serde_yaml::to_value(http)?);
    }
    if let Some(async_api) = &document.async_api {
        root.insert("async_api".into(), serde_yaml::to_value(async_api)?);
    }
    if !document.signatures.is_empty() {
        root.insert(
            "signatures".into(),
            serde_yaml::to_value(&document.signatures)?,
        );
    }
    if !document.resources.is_empty() {
        root.insert(
            "resources".into(),
            serde_yaml::to_value(&document.resources)?,
        );
    }
    ensure!(
        document
            .rules
            .iter()
            .all(|rule| matches!(rule, PolicyRule::Native(_))),
        "internal value rules cannot be authored; use root json.fields or mysql.tables"
    );
    let mut rules = vec![];
    let mut redis_rules = vec![];
    let mut recording_root = Mapping::new();
    let recording_id = recording::selected(&document.rules, document.source_revision.as_deref())?;
    let resource_names = resources::names(&document.resources)?;
    let compact_captures = compact_capture_suffix(&document);
    let capture_first = document.rules.iter().filter(|rule| matches!(rule,
        PolicyRule::Native(rule) if matches!(rule.effect, crate::policy::NativeEffect::CaptureHttp(_))));
    let remaining = document.rules.iter().filter(|rule| !matches!(rule,
        PolicyRule::Native(rule) if matches!(rule.effect, crate::policy::NativeEffect::CaptureHttp(_))));
    for rule in capture_first.chain(remaining) {
        if recording_id.as_deref() == Some(rule.id())
            && recording::compact(
                rule,
                document.source_revision.as_deref(),
                &mut recording_root,
            )?
        {
            continue;
        }
        if signatures::compact(rule, &document.signatures, &mut root)? {
            continue;
        }
        if api::compact(rule, &mut root)? {
            continue;
        }
        if (!capture_response(rule) || compact_captures.contains(rule.id()))
            && http::compact(rule, &document.resources, &mut root)?
        {
            continue;
        }
        if dependency_lifetimes::compact(rule, &document.resources, &mut root)? {
            continue;
        }
        if redis_keys::compact(rule, &mut root)? {
            continue;
        }
        let belongs_redis = redis_rule(rule);
        let mut rule = serde_yaml::to_value(rule)?;
        walk::compact_rule(&mut rule, document.source_revision.as_deref())?;
        resources::compact(&mut rule, &resource_names)?;
        if belongs_redis {
            redis_rules.push(rule)
        } else {
            rules.push(rule)
        };
    }
    if !redis_rules.is_empty() {
        let redis = root
            .entry(Value::String("redis".into()))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        redis
            .as_mapping_mut()
            .expect("serialized Redis settings mapping")
            .insert("rules".into(), Value::Sequence(redis_rules));
    }
    if !rules.is_empty() {
        root.insert("rules".into(), Value::Sequence(rules));
    }
    // Recording scope is the final authoring section regardless of native ID
    // order or whether earlier declarations retain compatibility rules.
    root.extend(recording_root);
    Ok(root.into())
}
