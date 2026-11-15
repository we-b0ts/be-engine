//! Prepared field rules and conflict validation, independent of application state.
use super::*;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
mod field_selection;
pub mod interaction;
#[derive(Debug, Clone, Serialize)]
pub struct CompiledRule {
    /// Fully expanded, self-contained rule, including its Source proof.
    pub rule: Rule,
    pub effect: RuleEffect,
    /// Delivery may only reuse declared time contracts from this same rule.
    pub delivery_time: BTreeMap<String, TimeContract>,
    pub capabilities: Vec<CapabilityId>,
    pub fingerprint: String,
    pub field_proofs: BTreeMap<String, Proof>,
    #[serde(skip)]
    pub codec_plan: std::sync::Arc<traffic_contract::codec::CodecPlan>,
    #[serde(skip)]
    pub execution_plan: std::sync::Arc<crate::plan::RuleExecutionPlan>,
}

impl PartialEq for CompiledRule {
    fn eq(&self, other: &Self) -> bool {
        self.rule == other.rule
            && self.effect == other.effect
            && self.delivery_time == other.delivery_time
            && self.capabilities == other.capabilities
            && self.fingerprint == other.fingerprint
            && self.field_proofs == other.field_proofs
            && self.execution_plan == other.execution_plan
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Compare,
    Deliver,
}

pub fn compile_rule(rule: &Rule, context: &crate::CompilationContext<'_>) -> Result<CompiledRule> {
    ensure!(
        !rule.id.is_empty()
            && rule.id.len() <= 128
            && rule
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte)),
        "rule id requires 1..128 ASCII identifier characters"
    );
    rule.proof.validate(false)?;
    validate_match(rule)?;
    field_selection::scalar(rule)?;
    validate_condition(rule)?;
    ensure!(
        !rule.contract.is_empty() && rule.contract.len() <= 128,
        "each rule requires 1..128 explicit field contracts"
    );
    validate_codec(&rule.codec, context)?;
    for (path, contract) in &rule.contract {
        if let FieldContract::Conditional { when, contract } = contract {
            ensure!(
                !matches!(contract.as_ref(), FieldContract::Conditional { .. }),
                "nested field conditions are unsupported"
            );
            when.validate(path)?;
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
        if let Some(definition) = contract.unconditional().registered_definition(false) {
            context.policies.prepare_definition(&definition)?;
        }
        validate_contract_binding(&rule.codec, path, contract, context)?;
        if let Some(time) = contract.unconditional().time() {
            time.clock_scope.validate(path)?;
            ensure!(
                !matches!(time.clock_scope, ClockScope::Entity { .. })
                    || (rule.surface == Surface::ApiResponse
                        && matches!(rule.slot, Slot::SseData(_))),
                "entity clock_scope requires an SSE identity sibling"
            );
            ensure!(
                time.format != TimestampFormat::CalendarDate || time.clock_scope.is_shared(),
                "calendar_date forbids clock_scope"
            );
            ensure!(
                match time.format {
                    TimestampFormat::CalendarDate => {
                        time.utc_offset.is_some() && time.clock_group.is_none()
                    }
                    TimestampFormat::Iso8601Naive | TimestampFormat::SqlDatetime => {
                        time.relation == TimeRelation::PreserveOffset || time.utc_offset.is_some()
                    }
                    _ => time.utc_offset.is_none(),
                },
                "calendar_date requires utc_offset and forbids clock_group; naive request_window times require utc_offset; relative timestamps need none; zoned and Unix formats forbid it"
            );
            time.offset()?;
        }
        match contract.unconditional() {
            FieldContract::Exact => {}
            FieldContract::Policy(_) => {}
            FieldContract::Time { anchor, .. } | FieldContract::Duration { anchor, .. } => {
                ensure!(
                    matches!(
                        anchor,
                        TimeAnchor::Observation | TimeAnchor::DependencyRequestStart
                    ),
                    "time contracts require the corresponding comparison event"
                );
            }
            FieldContract::Unordered => {}
            FieldContract::IdentityAnchor => {
                anyhow::bail!("identity anchors are internal comparator decisions")
            }
            FieldContract::Identity { prefix, format } => {
                interaction::validate_identity(rule, prefix, *format)?;
            }
            FieldContract::Conditional { .. } => unreachable!("nested field conditions rejected"),
        }
    }
    validate_field_overlaps(&rule.contract, context)?;
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
        effect: if rule.surface == Surface::DependencyResponse
            && (!matches!(rule.slot, Slot::SqlField(_) | Slot::RedisValue(_))
                || !delivery_time.is_empty())
        {
            RuleEffect::Deliver
        } else {
            RuleEffect::Compare
        },
        delivery_time,
        capabilities: capabilities.into_iter().collect(),
        fingerprint: digest("traffic-policy/rule/v1", &(rule, context.semantics()))?,
        field_proofs: rule
            .contract
            .keys()
            .map(|path| (path.clone(), rule.proof.clone()))
            .collect(),
        codec_plan: std::sync::Arc::new(crate::compiler::compile_codec(&rule.codec, context)?),
        execution_plan: std::sync::Arc::new(super::validate_rule_coverage(rule, context)?),
    })
}

fn validate_match(rule: &Rule) -> Result<()> {
    let selector = &rule.selector;
    ensure!(
        selector
            .resource
            .as_ref()
            .is_some_and(|r| r.protocol == Protocol::Mysql)
            || (selector.tables.is_empty()
                && selector.table_patterns.is_empty()
                && selector.table_series.is_none()),
        "SQL table selectors require a MySQL dependency resource"
    );
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
    if field_selection::validate(rule, resource)? {
        return Ok(());
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
            let values = traffic_protocol_mysql::value_template::validate_selector(
                selector.sql.as_deref().context("SQL template is absent")?,
                &selector.tables,
                &selector.table_patterns,
                selector.table_series.as_ref(),
            )?;
            if let Slot::SqlValue(index) = &rule.slot {
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

pub fn validate_codec(codec: &Codec, context: &crate::CompilationContext<'_>) -> Result<()> {
    crate::compiler::compile_codec(codec, context).map(|_| ())
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
        ensure!(
            !matches!(scalar, SourceScalar::Null),
            "Source request conditions require a non-null scalar"
        );
        if let SourceScalar::String(value) = scalar {
            ensure!(value.len() <= 1024, "Source condition scalar is too long");
        }
    }
    Ok(())
}

pub use traffic_contract::path::validate_pointer;

fn validate_field_overlaps(
    fields: &BTreeMap<String, FieldContract>,
    context: &crate::CompilationContext<'_>,
) -> Result<()> {
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
                fields[parent].supports_child_rules(context.policies)?
                    && child_segments[parent_length] == "*",
                "overlapping contracts at {left:?} and {right:?}; child contracts require unordered element scope"
            );
        }
    }
    Ok(())
}

pub fn validate_rule_overlaps(
    rules: &[CompiledRule],
    context: &crate::CompilationContext<'_>,
) -> Result<()> {
    for (index, left) in rules.iter().enumerate() {
        for right in &rules[index + 1..] {
            if left.rule.surface != right.rule.surface
                || !left.rule.slot.overlaps(&right.rule.slot)
                || !selectors_overlap(&left.rule.selector, &right.rule.selector)
                || !super::native_compile::ownership::value_sql_slots_overlap(
                    &left.rule,
                    &right.rule,
                )
                || disjoint_conditions(left.rule.when.as_ref(), right.rule.when.as_ref())
            {
                continue;
            }
            ensure!(
                codecs_compatible(&left.rule.codec, &right.rule.codec, context),
                "rules {:?} and {:?} select incompatible codecs or wire types for the same payload scope",
                left.rule.id,
                right.rule.id
            );
            for left_path in left.rule.contract.keys() {
                for right_path in right.rule.contract.keys() {
                    let overlap = crate::compiler::fields_overlap(
                        &left.rule.codec,
                        left_path,
                        &right.rule.codec,
                        right_path,
                        context,
                    )?;
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
    super::native_compile::ownership::value_sql_scopes_overlap(left, right)
}

pub fn key_scopes_overlap(left: Option<&KeySelector>, right: Option<&KeySelector>) -> bool {
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
    left == right || traffic_protocol_http::path_pattern::path_patterns_overlap(left, right)
}

fn codecs_compatible(left: &Codec, right: &Codec, context: &crate::CompilationContext<'_>) -> bool {
    let mut merged = left.clone();
    crate::compiler::merge_codec(&mut merged, right, context).is_ok()
}

pub fn disjoint_conditions(
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

pub fn validate_api(api: &str) -> Result<()> {
    let (_, path) = traffic_protocol_http::path_pattern::api_selector(api)
        .context("match.api requires a valid 'METHOD /path' selector")?;
    validate_path(path)
}

pub fn validate_path(path: &str) -> Result<()> {
    ensure!(
        path.len() <= 4096 && !path.contains([' ', '\t']),
        "path must be bounded and contain no whitespace"
    );
    traffic_protocol_http::path_pattern::validate_path_selector(path)
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

pub fn compile_codec(
    codec: &Codec,
    context: &crate::CompilationContext<'_>,
) -> Result<traffic_contract::codec::CodecPlan> {
    traffic_contract::codec::CodecPlan::compile(codec, context.codecs)
}

pub fn fields_overlap(
    left: &Codec,
    left_path: &str,
    right: &Codec,
    right_path: &str,
    context: &crate::CompilationContext<'_>,
) -> Result<bool> {
    ensure!(
        left.id() == right.id(),
        "overlapping values use different codecs"
    );
    let left_configuration = serde_json::from_value(left.configuration().clone())?;
    let right_configuration = serde_json::from_value(right.configuration().clone())?;
    context.codecs.fields_overlap(
        left.id(),
        &left_configuration,
        left_path,
        &right_configuration,
        right_path,
    )
}

pub fn merge_codec(
    codec: &mut Codec,
    next: &Codec,
    context: &crate::CompilationContext<'_>,
) -> Result<()> {
    if codec == next {
        return Ok(());
    }
    ensure!(
        codec.id() == next.id(),
        "selected rules disagree on the payload codec"
    );
    let left = serde_json::from_value(codec.configuration().clone())?;
    let right = serde_json::from_value(next.configuration().clone())?;
    let configuration = context.codecs.merge(codec.id(), &[&left, &right])?;
    *codec = Codec::registered(codec.id().to_owned(), serde_json::to_value(configuration)?)?;
    Ok(())
}
