//! Pure validation and compilation into closed typed effects; no legacy YAML lowering.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::*;
mod interaction;
mod order;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledPolicy {
    pub rules: Vec<CompiledRule>,
    pub native: Vec<CompiledNativeRule>,
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
    let document = decode_policy(yaml)?;
    compile_policy(&document)?;
    Ok(document)
}

/// Parse and validate once when the caller needs the compiled policy.
pub fn parse_and_compile_policy(yaml: &str) -> Result<CompiledPolicy> {
    compile_policy(&decode_policy(yaml)?)
}

fn decode_policy(yaml: &str) -> Result<TrafficPolicy> {
    serde_yaml::from_str(yaml).context("invalid traffic-policy/v1 document")
}

pub fn compile_policy(document: &TrafficPolicy) -> Result<CompiledPolicy> {
    let document = super::authoring::expanded(document)?;
    compile_expanded(&document)
}

fn compile_expanded(document: &TrafficPolicy) -> Result<CompiledPolicy> {
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
    let mut native = vec![];
    for rule in &document.rules {
        ensure!(ids.insert(rule.id()), "duplicate rule id {:?}", rule.id());
        match rule {
            PolicyRule::Value(rule) => rules
                .push(compile_rule(rule).with_context(|| format!("invalid rule {:?}", rule.id))?),
            PolicyRule::Native(rule) => native.push(compile_native(rule)?),
        }
    }
    rules.sort_by(|left, right| left.rule.id.cmp(&right.rule.id));
    order::native(&mut native);
    validate_rule_overlaps(&rules)?;
    interaction::validate_bindings(&rules)?;
    validate_field_claims(&rules, &native)?;
    let mut expanded = document.rules.iter().collect::<Vec<_>>();
    order::expanded(&mut expanded);
    let runtime = rules
        .iter()
        .map(|rule| RuntimeIdentity {
            id: &rule.rule.id,
            surface: rule.rule.surface,
            selector: &rule.rule.selector,
            slot: &rule.rule.slot,
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
            runtime: digest(
                "traffic-policy/runtime/v1",
                &(
                    runtime,
                    native
                        .iter()
                        .filter(|rule| {
                            matches!(rule.domain, NativeDomain::Runtime | NativeDomain::Input)
                                || affects_snapshot(rule)
                        })
                        .map(|rule| &rule.fingerprint)
                        .collect::<Vec<_>>(),
                ),
            )?,
            capture: digest(
                "traffic-policy/capture/v1",
                &native
                    .iter()
                    .filter(|rule| rule.domain == NativeDomain::Capture || affects_snapshot(rule))
                    .map(|rule| &rule.fingerprint)
                    .collect::<Vec<_>>(),
            )?,
            classification: digest(
                "traffic-policy/classification/v1",
                &native
                    .iter()
                    .filter(|rule| rule.domain == NativeDomain::Classification)
                    .map(|rule| &rule.fingerprint)
                    .collect::<Vec<_>>(),
            )?,
        },
        rules,
        native,
    })
}

#[derive(Serialize)]
struct RuntimeIdentity<'a> {
    id: &'a str,
    surface: Surface,
    selector: &'a MatchSpec,
    slot: &'a Slot,
    codec: &'a Codec,
    contract: &'a BTreeMap<String, FieldContract>,
    when: Option<&'a SourceCondition>,
    delivery_time: &'a BTreeMap<String, TimeContract>,
    effect: RuleEffect,
    capabilities: &'a [CapabilityId],
}

/// Redis process GET selectors also govern validated bootstrap seed admission.
/// Their delivery and acquisition identity cannot be treated as unused-only.
fn affects_snapshot(rule: &CompiledNativeRule) -> bool {
    matches!(&rule.rule.effect, NativeEffect::ProcessOwned(effect)
        if matches!(&effect.selector, super::native::ProcessSelector::Redis {operation,..} if operation == "GET"))
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
        if let FieldContract::Conditional { when, contract } = contract {
            ensure!(
                !matches!(contract.as_ref(), FieldContract::Conditional { .. }),
                "nested field conditions are unsupported"
            );
            ensure!(
                when.relative_pointer.starts_with("../") && !when.relative_pointer.contains('*'),
                "field condition requires one exact sibling pointer such as ../status"
            );
            validate_pointer(&when.relative_pointer[2..], false)?;
            ensure!(
                when.relative_pointer[3..]
                    .split('/')
                    .all(|segment| !matches!(segment, "." | "..")),
                "field condition cannot escape its sibling scope"
            );
            ensure!(
                !path.is_empty() && (1..=32).contains(&when.not_in.len()),
                "field condition requires a non-root field and 1..32 excluded scalars"
            );
            let kinds = when
                .not_in
                .iter()
                .map(std::mem::discriminant)
                .collect::<Vec<_>>();
            ensure!(
                kinds.iter().all(|kind| *kind == kinds[0]),
                "field condition constants must have the same scalar type"
            );
        }
        if let Some(time) = contract.unconditional().time()
            && let Some(group) = &time.clock_group
        {
            ensure!(
                !group.is_empty()
                    && group.len() <= 64
                    && group
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
                "clock_group requires a bounded Source-proven identifier"
            );
        }
        validate_pointer(path, true)?;
        validate_contract_binding(&rule.codec, path, contract)?;
        if let Some(time) = contract.unconditional().time() {
            ensure!(
                match time.format {
                    TimestampFormat::Iso8601Naive | TimestampFormat::SqlDatetime => {
                        time.relation == TimeRelation::PreserveOffset || time.utc_offset.is_some()
                    }
                    _ => time.utc_offset.is_none(),
                },
                "naive request_window times require utc_offset; relative times need none; zoned and Unix formats forbid it"
            );
            time.offset()?;
        }
        match contract.unconditional() {
            FieldContract::Time { anchor, .. } | FieldContract::Duration { anchor, .. } => {
                ensure!(
                    *anchor == TimeAnchor::DependencyRequestStart,
                    "time contracts require the corresponding dependency request start"
                );
            }
            FieldContract::Unordered => {}
            FieldContract::Identity {
                binding,
                prefix,
                format,
            } => {
                interaction::validate_identity(rule, binding, prefix, *format)?;
            }
            FieldContract::Conditional { .. } => unreachable!("nested field conditions rejected"),
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
                && selector.hash_field.is_none()
                && selector.path.is_none()
                && selector.sql.is_none(),
            "api.response cannot select a dependency resource or operation"
        );
        interaction::validate_slot(rule)?;
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
    if let Some(field) = &selector.hash_field {
        ensure!(
            resource.protocol == Protocol::Redis
                && operation == "HGET"
                && rule.surface == Surface::DependencyResponse,
            "hash_field selects only a Redis HGET response value"
        );
        validate_key(field)?;
    }
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
            if resource.protocol == Protocol::Memcached {
                ensure!(
                    matches!(
                        (rule.surface, operation),
                        (Surface::DependencyRequest, "SET")
                            | (Surface::DependencyResponse, "GET" | "GETS")
                    ),
                    "installed Memcached value slots support request SET and response GET/GETS"
                );
            }
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
                matches!(operation, "COM_QUERY" | "COM_STMT_EXECUTE"),
                "MySQL value slots require COM_QUERY or COM_STMT_EXECUTE"
            );
            ensure!(
                matches!(rule.slot, Slot::SqlValue(_) | Slot::SqlColumn(_))
                    && selector.key.is_none()
                    && selector.path.is_none(),
                "MySQL values require slot: {{sql_value: index}} or {{sql_column: name}}"
            );
            ensure!(
                matches!(
                    (&rule.slot, rule.surface),
                    (Slot::SqlValue(_), Surface::DependencyRequest)
                        | (Slot::SqlColumn(_), Surface::DependencyResponse)
                ),
                "SQL slot and comparison surface disagree"
            );
            if let Slot::SqlColumn(column) = &rule.slot {
                text(column, "SQL column", 256)?;
            }
            text(
                selector
                    .sql
                    .as_deref()
                    .context("MySQL requires an explicit SQL selector")?,
                "match.sql",
                65536,
            )?;
            let sql = selector.sql.as_deref().expect("SQL selector was required");
            ensure!(
                !sql.contains("{{table}}"),
                "generic SQL slots select an exact physical table; bounded table families use a typed native effect"
            );
            let tokens = crate::mysql::sql::tokens(sql)
                .context("SQL selector cannot be tokenized completely")?;
            ensure!(
                !tokens.is_empty()
                    && tokens.len() <= crate::mysql::sql::bounds::MAX_TOKENS
                    && !tokens.iter().any(|token| token.is(";"))
                    && crate::mysql::access::analyze_sql(sql).statements_complete,
                "SQL selector requires one bounded complete statement without a statement separator"
            );
            if let Slot::SqlValue(index) = &rule.slot {
                let values = tokens
                    .iter()
                    .filter(|token| **token == crate::mysql::sql::Token::Placeholder)
                    .count();
                ensure!(
                    *index < values,
                    "SQL value index {index} exceeds {values} explicit placeholder slots"
                );
            }
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
        key.exact.is_some() != (key.numeric || key.prefix.is_some() || key.suffix.is_some()),
        "key requires either exact or bounded prefix/suffix"
    );
    ensure!(
        !key.numeric || key.exact.is_none(),
        "numeric keys use affixes, not an exact key"
    );
    for value in [&key.exact, &key.prefix, &key.suffix].into_iter().flatten() {
        if key.numeric && value.is_empty() {
            continue;
        }
        ensure!(
            !value.is_empty() && value.len() <= 4096,
            "key selector is empty or too long"
        );
    }
    Ok(())
}

pub(crate) fn validate_codec(codec: &Codec) -> Result<()> {
    let Codec::Protobuf(codec) = codec else {
        return Ok(());
    };
    ensure!(
        codec.fields.len() <= 256,
        "Protobuf accepts at most 256 explicit field bindings"
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
                || !left.rule.slot.overlaps(&right.rule.slot)
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
    if let (Some(left), Some(right)) = (&left.resource, &right.resource)
        && (left.protocol != right.protocol
            || left.endpoint.port != right.endpoint.port
            || !left
                .endpoint
                .host
                .eq_ignore_ascii_case(&right.endpoint.host)
            || optional_disjoint(&left.database, &right.database)
            || optional_disjoint(&left.username, &right.username))
    {
        return false;
    }
    if !key_scopes_overlap(left.key.as_ref(), right.key.as_ref())
        || !key_scopes_overlap(left.hash_field.as_ref(), right.hash_field.as_ref())
    {
        return false;
    }
    super::native_compile::ownership::exact_sql_scopes_overlap(
        left.sql.as_deref(),
        right.sql.as_deref(),
    )
}

pub(crate) fn key_scopes_overlap(left: Option<&KeySelector>, right: Option<&KeySelector>) -> bool {
    if let (Some(left), Some(right)) = (left, right) {
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

pub(crate) fn disjoint_conditions(
    left: Option<&SourceCondition>,
    right: Option<&SourceCondition>,
) -> bool {
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

pub(super) fn validate_api(api: &str) -> Result<()> {
    let selector = api
        .parse::<crate::RecordingApi>()
        .context("match.api requires a valid 'METHOD /path' selector")?;
    validate_path(selector.path_pattern())
}

pub(crate) fn validate_path(path: &str) -> Result<()> {
    ensure!(
        path.len() <= 4096 && !path.contains([' ', '\t']),
        "path must be bounded and contain no whitespace"
    );
    crate::path_pattern::validate_path_selector(path)
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
