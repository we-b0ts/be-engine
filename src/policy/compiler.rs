//! Pure validation and compilation into closed typed effects; no legacy YAML lowering.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::*;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledPolicy {
    pub rules: Vec<CompiledRule>,
    pub fingerprints: PolicyFingerprints,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledRule {
    /// Fully expanded, self-contained rule, including its Source proof.
    pub rule: Rule,
    pub effect: RuleEffect,
    /// Delivery may only reuse declared time contracts from this same rule.
    pub delivery_time: BTreeMap<String, TimeContract>,
    pub capabilities: Vec<CapabilityId>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Compare,
    Deliver,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyFingerprints {
    pub full: String,
    pub runtime: String,
    pub capture: String,
    pub classification: String,
}

pub fn parse_policy(yaml: &str) -> Result<TrafficPolicy> {
    let document: TrafficPolicy =
        serde_yaml::from_str(yaml).context("invalid traffic-policy/v1 document")?;
    compile_policy(&document)?;
    Ok(document)
}

pub fn compile_policy(document: &TrafficPolicy) -> Result<CompiledPolicy> {
    ensure!(
        document.format == POLICY_FORMAT,
        "policy format must be {POLICY_FORMAT:?}"
    );
    ensure!(
        document.rules.len() <= 4096,
        "policy contains more than 4096 rules"
    );
    let mut ids = BTreeSet::new();
    let mut rules = Vec::with_capacity(document.rules.len());
    for rule in &document.rules {
        ensure!(
            ids.insert(rule.id.as_str()),
            "duplicate rule id {:?}",
            rule.id
        );
        rules.push(compile_rule(rule).with_context(|| format!("invalid rule {:?}", rule.id))?);
    }
    rules.sort_by(|left, right| left.rule.id.cmp(&right.rule.id));
    validate_rule_overlaps(&rules)?;
    let expanded = rules.iter().map(|rule| &rule.rule).collect::<Vec<_>>();
    let runtime = rules
        .iter()
        .map(|rule| RuntimeIdentity {
            id: &rule.rule.id,
            surface: rule.rule.surface,
            selector: &rule.rule.selector,
            slot: rule.rule.slot,
            codec: &rule.rule.codec,
            contract: &rule.rule.contract,
            when: rule.rule.when.as_ref(),
            delivery_time: &rule.delivery_time,
            effect: rule.effect,
            capabilities: &rule.capabilities,
        })
        .collect::<Vec<_>>();
    Ok(CompiledPolicy {
        fingerprints: PolicyFingerprints {
            full: digest("traffic-policy/full/v1", &expanded)?,
            runtime: digest("traffic-policy/runtime/v1", &runtime)?,
            capture: digest("traffic-policy/capture/v1", &Vec::<String>::new())?,
            classification: digest("traffic-policy/classification/v1", &Vec::<String>::new())?,
        },
        rules,
    })
}

#[derive(Serialize)]
struct RuntimeIdentity<'a> {
    id: &'a str,
    surface: Surface,
    selector: &'a MatchSpec,
    slot: Slot,
    codec: &'a Codec,
    contract: &'a BTreeMap<String, FieldContract>,
    when: Option<&'a SourceCondition>,
    delivery_time: &'a BTreeMap<String, TimeContract>,
    effect: RuleEffect,
    capabilities: &'a [CapabilityId],
}

pub fn compile_rule(rule: &Rule) -> Result<CompiledRule> {
    ensure!(
        !rule.id.is_empty()
            && rule.id.len() <= 128
            && rule
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte)),
        "rule id requires 1..128 ASCII identifier characters"
    );
    text(&rule.proof.source, "proof.source", 2048)?;
    text(&rule.proof.fact, "proof.fact", 4096)?;
    validate_match(rule)?;
    validate_condition(rule)?;
    ensure!(
        !rule.contract.is_empty() && rule.contract.len() <= 128,
        "each rule requires 1..128 explicit field contracts"
    );
    validate_codec(&rule.codec)?;
    for (path, contract) in &rule.contract {
        if let Some(time) = contract.time() {
            if let Some(group) = &time.clock_group {
                ensure!(
                    !group.is_empty()
                        && group.len() <= 64
                        && group
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
                    "clock_group requires a bounded Source-proven identifier"
                );
            }
        }
        validate_pointer(path, true)?;
        validate_contract_binding(&rule.codec, path, contract)?;
        if let Some(time) = contract.time() {
            ensure!(
                (time.format == TimestampFormat::Iso8601Naive) == time.utc_offset.is_some(),
                "iso8601_naive requires explicit utc_offset; other formats carry their own timezone or use Unix time"
            );
            time.offset()?;
        }
        match contract {
            FieldContract::Time { anchor, .. } | FieldContract::Duration { anchor, .. } => {
                ensure!(
                    rule.surface != Surface::ApiResponse || *anchor == TimeAnchor::ApiRequestStart,
                    "API response time contracts require case.request_start"
                );
                ensure!(
                    rule.surface != Surface::DependencyRequest
                        || *anchor != TimeAnchor::DependencyDelivery,
                    "dependency requests cannot depend on a future response-delivery clock"
                );
            }
            FieldContract::Unordered => {}
        }
    }
    validate_field_overlaps(&rule.contract)?;
    let mut delivery_time = BTreeMap::new();
    if let Some(delivery) = &rule.delivery {
        ensure!(
            rule.surface == Surface::DependencyResponse,
            "delivery is valid only on dependency.response"
        );
        ensure!(
            !delivery.rebase_time.is_empty(),
            "delivery.rebase_time must select at least one declared timestamp"
        );
        for path in &delivery.rebase_time {
            let time = rule
                .contract
                .get(path)
                .and_then(FieldContract::time)
                .with_context(|| {
                    format!("delivery.rebase_time {path:?} is not a time contract in this rule")
                })?;
            ensure!(
                delivery_time.insert(path.clone(), time).is_none(),
                "duplicate delivery time selector {path:?}"
            );
        }
    }
    let mut capabilities = rule
        .contract
        .values()
        .map(CapabilityId::for_contract)
        .collect::<BTreeSet<_>>();
    if !delivery_time.is_empty() {
        capabilities.insert(CapabilityId::RebaseTime);
    }
    Ok(CompiledRule {
        rule: rule.clone(),
        effect: if rule.surface == Surface::DependencyResponse {
            RuleEffect::Deliver
        } else {
            RuleEffect::Compare
        },
        delivery_time,
        capabilities: capabilities.into_iter().collect(),
        fingerprint: digest("traffic-policy/rule/v1", rule)?,
    })
}

fn validate_match(rule: &Rule) -> Result<()> {
    let selector = &rule.selector;
    if let Some(api) = &selector.api {
        validate_api(api)?;
    }
    if rule.surface == Surface::ApiResponse {
        ensure!(selector.api.is_some(), "api.response requires match.api");
        ensure!(
            selector.resource.is_none()
                && selector.operation.is_none()
                && selector.key.is_none()
                && selector.path.is_none()
                && selector.sql.is_none(),
            "api.response cannot select a dependency resource or operation"
        );
        ensure!(rule.slot == Slot::Body, "api.response requires slot: body");
        return Ok(());
    }
    let resource = selector
        .resource
        .as_ref()
        .context("dependency rules require match.resource")?;
    resource.endpoint.validate()?;
    if let Some(username) = &resource.username {
        text(username, "resource.username", 256)?;
        ensure!(
            matches!(resource.protocol, Protocol::Redis | Protocol::Mysql),
            "username identity is supported only for Redis and MySQL"
        );
    }
    let operation = selector
        .operation
        .as_deref()
        .context("dependency rules require an explicit operation")?;
    ensure!(
        !operation.is_empty()
            && operation.len() <= 64
            && operation
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
        "operation must be an exact uppercase protocol operation"
    );
    match resource.protocol {
        Protocol::Http => {
            ensure!(
                rule.slot == Slot::Body
                    && selector.key.is_none()
                    && selector.sql.is_none()
                    && resource.database.is_none(),
                "HTTP selects body and path, not key/database/SQL"
            );
            validate_path(
                selector
                    .path
                    .as_deref()
                    .context("HTTP resource requires match.path")?,
            )?;
        }
        Protocol::Redis | Protocol::Memcached => {
            ensure!(
                rule.slot == Slot::Value && selector.path.is_none() && selector.sql.is_none(),
                "Redis/Memcached value rules require slot: value without HTTP path or SQL"
            );
            validate_key(
                selector
                    .key
                    .as_ref()
                    .context("value rules require an explicit key selector")?,
            )?;
            match (&resource.protocol, &resource.database) {
                (Protocol::Redis, Some(Database::Index(index))) => {
                    ensure!(*index >= 0, "Redis database index must be nonnegative")
                }
                (Protocol::Redis, None) | (Protocol::Memcached, None) => {}
                _ => anyhow::bail!(
                    "Redis database must be an integer and Memcached has no database selector"
                ),
            }
        }
        Protocol::Mysql => {
            ensure!(
                rule.slot == Slot::Value && selector.key.is_none() && selector.path.is_none(),
                "MySQL scalar rules require slot: value without key/HTTP path"
            );
            text(
                selector
                    .sql
                    .as_deref()
                    .context("MySQL requires an explicit SQL selector")?,
                "match.sql",
                65536,
            )?;
            if let Some(database) = &resource.database {
                text(
                    database.name().context("MySQL database must be a name")?,
                    "resource.database",
                    256,
                )?;
            }
        }
    }
    Ok(())
}

fn validate_key(key: &KeySelector) -> Result<()> {
    ensure!(
        key.exact.is_some() != (key.prefix.is_some() || key.suffix.is_some()),
        "key requires either exact or bounded prefix/suffix"
    );
    for value in [&key.exact, &key.prefix, &key.suffix].into_iter().flatten() {
        ensure!(
            !value.is_empty() && value.len() <= 4096,
            "key selector is empty or too long"
        );
    }
    Ok(())
}

fn validate_codec(codec: &Codec) -> Result<()> {
    let Codec::Protobuf(codec) = codec else {
        return Ok(());
    };
    ensure!(
        !codec.fields.is_empty() && codec.fields.len() <= 256,
        "Protobuf requires 1..256 explicit field bindings"
    );
    let mut paths = BTreeSet::new();
    for (name, field) in &codec.fields {
        validate_pointer(name, true)?;
        ensure!(
            !name.is_empty(),
            "Protobuf field bindings require non-root named selectors"
        );
        ensure!(
            !field.field_path.is_empty() && field.field_path.len() <= 32,
            "Protobuf field_path requires 1..32 field numbers"
        );
        ensure!(
            field
                .field_path
                .iter()
                .all(|number| (1..=536_870_911).contains(number)
                    && !(19_000..=19_999).contains(number)),
            "invalid or reserved Protobuf field number"
        );
        ensure!(
            paths.insert(&field.field_path),
            "two named Protobuf bindings select the same wire field"
        );
    }
    for (parent_name, parent) in &codec.fields {
        for (child_name, child) in &codec.fields {
            if child.field_path.len() <= parent.field_path.len()
                || !child.field_path.starts_with(&parent.field_path)
            {
                continue;
            }
            ensure!(
                parent.field_type == ProtobufType::Message,
                "Protobuf scalar binding {parent_name:?} cannot have a descendant wire field"
            );
            let prefix = if parent.repeated {
                format!("{parent_name}/*/")
            } else {
                format!("{parent_name}/")
            };
            ensure!(
                child_name.starts_with(&prefix),
                "Protobuf descendant {child_name:?} must retain the explicit message scope of {parent_name:?}"
            );
        }
    }
    Ok(())
}

fn validate_condition(rule: &Rule) -> Result<()> {
    let Some(condition) = &rule.when else {
        return Ok(());
    };
    ensure!(
        rule.selector.api.is_some(),
        "Source request conditions require an explicit match.api"
    );
    ensure!(
        !condition.request_body_json.is_empty() && condition.request_body_json.len() <= 16,
        "Source request conditions require 1..16 scalar predicates"
    );
    for (path, predicate) in &condition.request_body_json {
        validate_pointer(path, false)?;
        ensure!(
            !path.is_empty(),
            "Source request conditions cannot select the entire body"
        );
        let scalar = match predicate {
            SourcePredicate::Equals(value) => &value.equals,
            SourcePredicate::NotEquals(value) => &value.not_equals,
        };
        if let SourceScalar::String(value) = scalar {
            ensure!(value.len() <= 1024, "Source condition scalar is too long");
        }
    }
    Ok(())
}

pub fn validate_pointer(pointer: &str, wildcard: bool) -> Result<()> {
    ensure!(
        pointer.len() <= 1024 && (pointer.is_empty() || pointer.starts_with('/')),
        "field selector requires a bounded JSON Pointer"
    );
    ensure!(
        !pointer.contains(['\r', '\n', '\0']),
        "field selector contains control characters"
    );
    for segment in pointer.split('/').skip(1) {
        ensure!(
            wildcard || segment != "*",
            "Source predicates require exact JSON Pointers"
        );
        let mut chars = segment.chars();
        while let Some(character) = chars.next() {
            if character == '~' {
                ensure!(
                    matches!(chars.next(), Some('0' | '1')),
                    "invalid JSON Pointer escape"
                );
            }
        }
    }
    Ok(())
}

fn validate_field_overlaps(fields: &BTreeMap<String, FieldContract>) -> Result<()> {
    let paths = fields.keys().collect::<Vec<_>>();
    for (index, left) in paths.iter().enumerate() {
        for right in &paths[index + 1..] {
            let left_segments = pointer_segments(left);
            let right_segments = pointer_segments(right);
            if !pointer_prefixes_overlap(&left_segments, &right_segments) {
                continue;
            }
            ensure!(
                left_segments.len() != right_segments.len(),
                "overlapping field selectors {left:?} and {right:?} own the same leaf"
            );
            let (parent, child_segments) = if left_segments.len() < right_segments.len() {
                (*left, &right_segments)
            } else {
                (*right, &left_segments)
            };
            let parent_length = pointer_segments(parent).len();
            ensure!(
                matches!(fields[parent], FieldContract::Unordered)
                    && child_segments[parent_length] == "*",
                "overlapping contracts at {left:?} and {right:?}; child contracts require unordered element scope"
            );
        }
    }
    Ok(())
}

fn validate_rule_overlaps(rules: &[CompiledRule]) -> Result<()> {
    for (index, left) in rules.iter().enumerate() {
        for right in &rules[index + 1..] {
            if left.rule.surface != right.rule.surface
                || left.rule.slot != right.rule.slot
                || !selectors_overlap(&left.rule.selector, &right.rule.selector)
                || disjoint_conditions(left.rule.when.as_ref(), right.rule.when.as_ref())
            {
                continue;
            }
            ensure!(
                codecs_compatible(&left.rule.codec, &right.rule.codec),
                "rules {:?} and {:?} select incompatible codecs or wire types for the same payload scope",
                left.rule.id,
                right.rule.id
            );
            for left_path in left.rule.contract.keys() {
                for right_path in right.rule.contract.keys() {
                    let overlap = match (&left.rule.codec, &right.rule.codec) {
                        (Codec::Protobuf(a), Codec::Protobuf(b)) => {
                            let a = &a.fields[left_path].field_path;
                            let b = &b.fields[right_path].field_path;
                            a.iter().zip(b).all(|(a, b)| a == b)
                        }
                        _ => pointer_prefixes_overlap(
                            &pointer_segments(left_path),
                            &pointer_segments(right_path),
                        ),
                    };
                    ensure!(
                        !overlap,
                        "rules {:?} and {:?} own overlapping fields {left_path:?}/{right_path:?}; combine contracts in one rule",
                        left.rule.id,
                        right.rule.id
                    );
                }
            }
        }
    }
    Ok(())
}

fn pointer_segments(pointer: &str) -> Vec<&str> {
    if pointer.is_empty() {
        Vec::new()
    } else {
        pointer.split('/').skip(1).collect()
    }
}

fn pointer_prefixes_overlap(left: &[&str], right: &[&str]) -> bool {
    left.iter()
        .zip(right)
        .all(|(left, right)| left == right || *left == "*" || *right == "*")
}

fn selectors_overlap(left: &MatchSpec, right: &MatchSpec) -> bool {
    if !optional_paths_overlap(left.api.as_deref(), right.api.as_deref(), true)
        || !optional_paths_overlap(left.path.as_deref(), right.path.as_deref(), false)
    {
        return false;
    }
    if let (Some(left), Some(right)) = (&left.operation, &right.operation)
        && left != right
    {
        return false;
    }
    if let (Some(left), Some(right)) = (&left.resource, &right.resource) {
        if left.protocol != right.protocol
            || left.endpoint.port != right.endpoint.port
            || !left
                .endpoint
                .host
                .eq_ignore_ascii_case(&right.endpoint.host)
            || optional_disjoint(&left.database, &right.database)
            || optional_disjoint(&left.username, &right.username)
        {
            return false;
        }
    }
    if let (Some(left), Some(right)) = (&left.key, &right.key) {
        if let Some(exact) = &left.exact {
            return right.matches(exact.as_bytes());
        }
        if let Some(exact) = &right.exact {
            return left.matches(exact.as_bytes());
        }
        if let (Some(left), Some(right)) = (&left.prefix, &right.prefix)
            && !left.starts_with(right)
            && !right.starts_with(left)
        {
            return false;
        }
        if let (Some(left), Some(right)) = (&left.suffix, &right.suffix)
            && !left.ends_with(right)
            && !right.ends_with(left)
        {
            return false;
        }
    }
    // SQL disjointness needs a protocol template proof; stay conservative here.
    true
}

fn optional_disjoint<T: PartialEq>(left: &Option<T>, right: &Option<T>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if left != right)
}

fn optional_paths_overlap(left: Option<&str>, right: Option<&str>, api: bool) -> bool {
    let (Some(mut left), Some(mut right)) = (left, right) else {
        return true;
    };
    if api {
        let (left_method, left_path) = left.split_once(' ').expect("validated API selector");
        let (right_method, right_path) = right.split_once(' ').expect("validated API selector");
        if left_method != right_method {
            return false;
        }
        left = left_path;
        right = right_path;
    }
    left == right || crate::path_pattern::path_patterns_overlap(left, right)
}

fn codecs_compatible(left: &Codec, right: &Codec) -> bool {
    match (left, right) {
        (Codec::Json, Codec::Json) => true,
        (Codec::Protobuf(left), Codec::Protobuf(right)) => {
            left.fields.iter().all(|(name, field)| {
                right.fields.get(name).is_none_or(|other| field == other)
                    && right.fields.values().all(|other| {
                        field.field_path != other.field_path
                            || field.field_type == other.field_type
                                && field.repeated == other.repeated
                    })
            })
        }
        _ => false,
    }
}

fn disjoint_conditions(left: Option<&SourceCondition>, right: Option<&SourceCondition>) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        return false;
    };
    left.request_body_json.iter().any(|(path, left)| {
        let Some(right) = right.request_body_json.get(path) else {
            return false;
        };
        match (left, right) {
            (SourcePredicate::Equals(left), SourcePredicate::Equals(right)) => {
                left.equals != right.equals
            }
            (SourcePredicate::Equals(left), SourcePredicate::NotEquals(right)) => {
                left.equals == right.not_equals
            }
            (SourcePredicate::NotEquals(left), SourcePredicate::Equals(right)) => {
                left.not_equals == right.equals
            }
            _ => false,
        }
    })
}

fn validate_api(api: &str) -> Result<()> {
    let (method, path) = api
        .split_once(' ')
        .context("match.api requires 'METHOD /path'")?;
    ensure!(
        !method.is_empty() && method.bytes().all(|byte| byte.is_ascii_uppercase()),
        "match.api method must be uppercase"
    );
    validate_path(path)
}

fn validate_path(path: &str) -> Result<()> {
    ensure!(
        path.len() <= 4096 && !path.contains([' ', '\t']),
        "path must be bounded and contain no whitespace"
    );
    if path == "/" {
        return Ok(());
    }
    crate::path_pattern::validate_path_pattern(path)
}

fn text(value: &str, name: &str, max: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= max && !value.contains(['\r', '\n', '\0']),
        "{name} must be a nonempty bounded single line"
    );
    Ok(())
}

pub fn digest<T: Serialize + ?Sized>(domain: &str, value: &T) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(value)?);
    Ok(format!("sha256:{:x}", hash.finalize()))
}
