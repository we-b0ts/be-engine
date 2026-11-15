//! Authoring documents resolve to fully explicit typed rules before compilation.
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer};
use serde_yaml::{Mapping, Value};

use super::{
    api, dependency_lifetimes, http, proof, recording, redis_keys, resources, signatures, walk,
};
use crate::{PolicyRule, TrafficPolicy};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub format: String,
    #[serde(default, deserialize_with = "declared_revision")]
    pub source_revision: Option<String>,
    #[serde(default)]
    pub time: crate::TimePolicy,
    #[serde(default)]
    pub recording: Option<recording::Declaration>,
    #[serde(default)]
    pub json: Option<crate::JsonPolicy>,
    #[serde(default)]
    pub mysql: Option<crate::MysqlPolicy>,
    #[serde(default)]
    pub redis: Option<RedisDocument>,
    #[serde(default)]
    pub http: Option<http::HttpDocument>,
    #[serde(default)]
    pub docx: Option<api::DocxDefinition>,
    #[serde(default)]
    pub localcache: Option<dependency_lifetimes::Declaration>,
    #[serde(default)]
    pub process_dependencies: Option<dependency_lifetimes::ProcessDeclaration>,
    #[serde(default, deserialize_with = "crate::strict_map::unique_map")]
    pub signatures: std::collections::BTreeMap<String, crate::SignatureDefinition>,
    #[serde(default)]
    pub api: Option<api::ApiDefinitions>,
    #[serde(default, deserialize_with = "recording::optional_async_api")]
    pub async_api: Option<std::collections::BTreeMap<String, crate::AsyncApiRules>>,
    #[serde(default, deserialize_with = "crate::strict_map::unique_map")]
    pub resources: std::collections::BTreeMap<String, crate::ResourceDeclaration>,
    #[serde(default)]
    pub rules: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisDocument {
    #[serde(default, deserialize_with = "redis_keys")]
    pub keys: Option<std::collections::BTreeMap<String, redis_keys::Entry>>,
    #[serde(default, deserialize_with = "redis_rules")]
    pub rules: Option<Vec<Value>>,
}

pub fn redis_keys<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<std::collections::BTreeMap<String, redis_keys::Entry>>, D::Error> {
    crate::strict_map::unique_map(deserializer).map(Some)
}

pub fn redis_rules<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<Value>>, D::Error> {
    Vec::deserialize(deserializer).map(Some)
}

pub fn declared_revision<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

pub fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
    context: &crate::AuthoringContext<'_>,
) -> Result<TrafficPolicy, D::Error> {
    let document = Document::deserialize(deserializer)?;
    let result = (|| -> anyhow::Result<TrafficPolicy> {
        if let Some(revision) = &document.source_revision {
            proof::revision(revision)?;
        }
        resources::validate(&document.resources)?;
        crate::signatures::validate(&document.signatures)?;
        let recording_async = document
            .recording
            .as_ref()
            .and_then(|recording| recording.async_api.as_ref());
        ensure!(
            document.async_api.is_none() || recording_async.is_none(),
            "async_api cannot be declared both at the top level and under recording"
        );
        let async_api = document.async_api.or_else(|| recording_async.cloned());
        let (redis, nested_rules) = redis_document(document.redis, context)?;
        let (http, http_rules) = http::expand(document.http, &document.resources, context)?;
        let mut declared_rules = document.rules;
        declared_rules.extend(recording::expand(
            document.recording,
            document.source_revision.as_deref(),
            context,
        )?);
        declared_rules.extend(nested_rules);
        declared_rules.extend(http_rules);
        declared_rules.extend(api::expand(
            document.api,
            &document.signatures,
            document.docx.as_ref(),
            context,
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
        Ok(TrafficPolicy {
            format: document.format,
            source_revision: document.source_revision,
            time: document.time,
            json: document.json,
            mysql: document.mysql,
            redis,
            http,
            async_api,
            signatures: document.signatures,
            resources: document.resources,
            rules,
        })
    })();
    result.map_err(serde::de::Error::custom)
}

pub fn redis_document(
    value: Option<RedisDocument>,
    context: &crate::AuthoringContext<'_>,
) -> Result<(Option<crate::RedisPolicy>, Vec<Value>)> {
    let Some(value) = value else {
        return Ok((None, vec![]));
    };
    let has_settings = value.keys.is_some();
    let (keys, generated) = redis_keys::expand(value.keys.unwrap_or_default(), context)?;
    let policy = if !has_settings && value.rules.is_some() {
        None
    } else {
        Some(crate::RedisPolicy { keys })
    };
    let mut rules = value.rules.unwrap_or_default();
    rules.extend(generated);
    Ok((policy, rules))
}

pub fn sort_rules(rules: &mut [PolicyRule]) {
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

pub fn capture_response(rule: &PolicyRule) -> bool {
    matches!(rule, PolicyRule::Native(rule)
        if matches!(rule.effect, crate::NativeEffect::CaptureHttpResponse(_)))
}

pub fn compact_capture_suffix(
    document: &TrafficPolicy,
    context: &crate::AuthoringContext<'_>,
) -> std::collections::BTreeSet<String> {
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
            http::compact(rule, &document.resources, &mut probe, context),
            Ok(true)
        ) {
            break;
        }
        selected.insert(rule.id().to_owned());
    }
    selected
}

pub fn redis_rule(rule: &PolicyRule) -> bool {
    let PolicyRule::Native(rule) = rule else {
        return false;
    };
    rule.selector
        .resource
        .as_ref()
        .is_some_and(|resource| resource.protocol == crate::Protocol::Redis)
        || matches!(
            rule.effect,
            crate::NativeEffect::RedisSequence(_)
                | crate::NativeEffect::RedisAppendStream
                | crate::NativeEffect::RedisReadCommutation(_)
                | crate::NativeEffect::RedisReadObservation(_)
                | crate::NativeEffect::RedisExpiryRefresh(_)
                | crate::NativeEffect::RedisActivityRefresh(_)
        )
        || matches!(&rule.effect, crate::NativeEffect::ProcessOwned(effect)
            if matches!(effect.selector, crate::native::ProcessSelector::Redis { .. } | crate::native::ProcessSelector::RedisPubsub(_)))
}

/// Typed callers can insert rules without a document context; normalize them
/// here too so compile, rendering and plan evidence bind the same Source.
pub fn expanded(document: &TrafficPolicy) -> Result<TrafficPolicy> {
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
        time: document.time.clone(),
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

pub fn compact_value(
    document: &TrafficPolicy,
    context: &crate::AuthoringContext<'_>,
) -> Result<Value> {
    let document = expanded(document)?;
    ensure!(
        document.format == crate::POLICY_FORMAT,
        "policy format must be traffic-policy/v3"
    );
    let mut root = Mapping::new();
    root.insert("format".into(), document.format.clone().into());
    if let Some(revision) = &document.source_revision {
        root.insert("source_revision".into(), revision.clone().into());
    }
    root.insert("time".into(), serde_yaml::to_value(&document.time)?);
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
    if let Some(async_api) = &document.async_api {
        let mut recording = Mapping::new();
        recording.insert("async_api".into(), serde_yaml::to_value(async_api)?);
        recording_root.insert("recording".into(), recording.into());
    }
    let recording_id = recording::selected(
        &document.rules,
        document.source_revision.as_deref(),
        context,
    )?;
    let resource_names = resources::names(&document.resources)?;
    let compact_captures = compact_capture_suffix(&document, context);
    let capture_first = document.rules.iter().filter(|rule| {
        matches!(rule,
        PolicyRule::Native(rule) if matches!(rule.effect, crate::NativeEffect::CaptureHttp(_)))
    });
    let remaining = document.rules.iter().filter(|rule| {
        !matches!(rule,
        PolicyRule::Native(rule) if matches!(rule.effect, crate::NativeEffect::CaptureHttp(_)))
    });
    for rule in capture_first.chain(remaining) {
        if recording_id.as_deref() == Some(rule.id())
            && recording::compact(
                rule,
                document.source_revision.as_deref(),
                &mut recording_root,
                context,
            )?
        {
            continue;
        }
        if signatures::compact(rule, &document.signatures, &mut root, context)? {
            continue;
        }
        if api::compact(rule, &mut root, context)? {
            continue;
        }
        if (!capture_response(rule) || compact_captures.contains(rule.id()))
            && http::compact(rule, &document.resources, &mut root, context)?
        {
            continue;
        }
        if dependency_lifetimes::compact(rule, &document.resources, &mut root)? {
            continue;
        }
        if redis_keys::compact(rule, &mut root, context)? {
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
