//! Global content formats retain protocol identity checks and reconstruct only
//! authenticated read-copy facts. Native key relations remain Replay obligations.
use super::*;
use crate::policy::native::{NativeKeyContract, NativeKeySelector};
use crate::value_codec::{CodecPlan, DecodedValue};
use crate::value_contract::time_copies::{TimeCopyLookup, TimeCopyPosition};

pub(super) fn compare(
    event: &Value,
    surface: Surface,
    source: &[u8],
    target: &[u8],
    context: &mut CompareContext<'_>,
) -> Result<Comparison> {
    let clocks = context.clocks;
    let command = event["command"]
        .as_str()
        .context("global JSON Redis command unavailable")?;
    let source_args: Vec<Vec<u8>> = if surface == Surface::DependencyRequest {
        serde_json::from_slice(source)?
    } else {
        arguments(event)?
    };
    let mut target_args: Vec<Vec<u8>> = if surface == Surface::DependencyRequest {
        serde_json::from_slice(target)?
    } else {
        arguments(event)?
    };
    if surface == Surface::DependencyRequest
        && let Some(normalized) = crate::replay::normalize_redis_expiration(
            command,
            &source_args,
            &target_args,
            clocks.dependency,
        )?
    {
        target_args = normalized;
    }
    if command == "PUBLISH" && surface == Surface::DependencyRequest {
        ensure!(
            source_args.len() == 2 && target_args.len() == 2 && source_args[0] == target_args[0],
            "global JSON Redis publish channel/arity changed"
        );
        return if let Some(plan) = &context.policy.global_json {
            global::compare(&source_args[1], &target_args[1], plan, &[], clocks)
        } else {
            ensure!(
                source_args[1] == target_args[1],
                "unselected Redis publish content changed"
            );
            Ok(Comparison::default())
        };
    }
    let before = crate::replay::redis_field_values(
        command,
        &source_args,
        (surface == Surface::DependencyResponse).then_some(source),
    )?;
    let after = crate::replay::redis_field_values(
        command,
        &target_args,
        (surface == Surface::DependencyResponse).then_some(target),
    )?;
    ensure!(
        before.len() == after.len(),
        "global JSON Redis storage inventory changed"
    );
    let mut comparison = Comparison::default();
    let mut allowed = BTreeSet::new();
    let mut key_obligations = BTreeSet::new();
    for (index, (before, after)) in before.iter().zip(&after).enumerate() {
        ensure!(
            before.hash_field == after.hash_field
                && before.container == after.container
                && before.argument == after.argument,
            "global JSON Redis storage identity changed"
        );
        if before.key != after.key {
            let owners = native_key_owners(
                context.policy,
                context.request,
                event,
                before.key,
                after.key,
                command,
            )?;
            ensure!(
                !owners.is_empty(),
                "global JSON Redis key changed without a native owner"
            );
            key_obligations.extend(owners);
            allowed.insert(if command == "MSET" {
                before
                    .argument
                    .context("MSET value position unavailable")?
                    .checked_sub(1)
                    .context("MSET key position unavailable")?
            } else {
                0
            });
        }
        match (before.payload, after.payload) {
            (Some(source), Some(target)) => {
                let mut checked = compare_value(event, before, after, source, target, context)?;
                if !checked.evaluated.is_empty() {
                    allowed.extend(before.argument);
                }
                checked.scope_schema_clocks(index);
                comparison.merge_and_validate(checked);
            }
            (None, None) => {}
            _ => anyhow::bail!("global JSON Redis value presence changed"),
        }
    }
    if surface == Surface::DependencyRequest {
        ensure!(
            source_args.len() == target_args.len(),
            "global JSON Redis argument inventory changed"
        );
        for (index, (source, target)) in source_args.iter().zip(&target_args).enumerate() {
            ensure!(
                allowed.contains(&index) || source == target,
                "unselected Redis argument {index} changed"
            );
        }
    }
    // Validate only content here. A changed native key needs its stateful,
    // independently replayed capture/reference proof before acceptance.
    if comparison.passed() {
        context.native_obligations.extend(key_obligations);
    }
    Ok(comparison)
}

fn compare_value(
    event: &Value,
    before: &crate::replay::RedisFieldValue<'_>,
    after: &crate::replay::RedisFieldValue<'_>,
    source: &[u8],
    target: &[u8],
    context: &CompareContext<'_>,
) -> Result<Comparison> {
    if let Some(database) = event["database"].as_i64()
        && let Some(field) = context
            .policy
            .redis
            .as_ref()
            .map(|policy| policy.field(database, before.key))
            .transpose()?
            .flatten()
        && crate::value_contract::redis_scalar::decode_field(source, field)?.is_some()
    {
        let mut comparison = compare_scalar(event, before, after, source, target, field, context)?;
        if let Some(plan) = &context.policy.global_json
            && crate::json_value::parse(source).is_some()
            && plan.fields.contains_key("")
        {
            comparison.merge_and_validate(global::compare(
                source,
                target,
                plan,
                &[],
                context.clocks,
            )?);
        }
        return Ok(comparison);
    }
    let fallback;
    let plan = if let Some(plan) = &context.policy.global_json {
        plan
    } else {
        fallback = crate::policy::JsonPolicy {
            fields: BTreeMap::new(),
        }
        .compile()?;
        &fallback
    };
    let Some((store, case)) = context.copies else {
        return global::compare(source, target, plan, &[], context.clocks);
    };
    let codec = CodecPlan::compile(&crate::policy::Codec::Json)?;
    let Ok(expected) = codec.decode(source) else {
        return global::compare(source, target, plan, &[], context.clocks);
    };
    let actual = codec
        .decode(target)
        .context("Target changed Source JSON encoding")?;
    let resource = observed_resource(event)?;
    let database = event["database"]
        .as_i64()
        .context("Redis copy lacks observed database")?;
    let source_position = crate::replay::redis_time_position(
        &resource.endpoint.host,
        resource.endpoint.port,
        database,
        before,
    );
    let target_position = crate::replay::redis_time_position(
        &resource.endpoint.host,
        resource.endpoint.port,
        database,
        after,
    );
    let proofs = proofs(
        store,
        case,
        source_position,
        target_position,
        &expected,
        plan,
        context.clocks,
    )?;
    global::compare_decoded_with_time_copies(&expected, &actual, plan, &[], context.clocks, &proofs)
}

fn compare_scalar(
    event: &Value,
    before: &crate::replay::RedisFieldValue<'_>,
    after: &crate::replay::RedisFieldValue<'_>,
    source: &[u8],
    target: &[u8],
    field: &crate::policy::GlobalField,
    context: &CompareContext<'_>,
) -> Result<Comparison> {
    let mut proofs = Vec::new();
    if let Some((store, case)) = context.copies
        && let Some(scalar) = crate::value_contract::redis_scalar::decode_field(source, field)?
        && let Some(time) = field
            .select_contract_with_clock(
                &scalar.logical,
                context
                    .clocks
                    .dependency
                    .source
                    .or(context.clocks.case.source),
            )?
            .time()
    {
        let resource = observed_resource(event)?;
        let database = event["database"]
            .as_i64()
            .context("scalar Redis copy lacks database")?;
        let source_position = crate::replay::redis_time_position(
            &resource.endpoint.host,
            resource.endpoint.port,
            database,
            before,
        );
        let target_position = crate::replay::redis_time_position(
            &resource.endpoint.host,
            resource.endpoint.port,
            database,
            after,
        );
        if let Some(lookup) = TimeCopyLookup::new_time(
            &time,
            source_position,
            target_position,
            "",
            "",
            &scalar.logical,
            "global.redis",
        ) && let Some(proof) = store.proof_prepared(case, &lookup.at("", ""))
        {
            proofs.push(proof);
        }
    }
    crate::value_contract::redis_scalar::compare(source, target, field, context.clocks, &proofs)
}

fn proofs(
    store: &TimeCopyStore,
    case: &str,
    source: TimeCopyPosition<'_>,
    target: TimeCopyPosition<'_>,
    decoded: &DecodedValue,
    plan: &crate::policy::CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Result<Vec<crate::value_contract::json::VerifiedTimeCopy>> {
    Ok(
        crate::value_contract::time_copies::global_leaves(&decoded.logical, plan, clocks)?
            .into_iter()
            .filter_map(|leaf| {
                let lookup = TimeCopyLookup::new_time(
                    &leaf.time,
                    source,
                    target,
                    &leaf.pattern,
                    &leaf.pattern,
                    &leaf.value,
                    GLOBAL_JSON_ID,
                )?;
                store.proof_prepared(case, &lookup.at(&leaf.pointer, &leaf.pattern))
            })
            .collect(),
    )
}

fn native_key_owners(
    policy: &CompiledPolicy,
    request: Option<&Value>,
    event: &Value,
    key: &[u8],
    target_key: &[u8],
    command: &str,
) -> Result<BTreeSet<String>> {
    let Some(request) = request else {
        return Ok(BTreeSet::new());
    };
    let method = request["method"]
        .as_str()
        .context("native key Source method unavailable")?;
    let uri: hyper::Uri = request["uri"]
        .as_str()
        .context("native key Source URI unavailable")?
        .parse()?;
    let body = capture(&request["body"])
        .ok()
        .and_then(|bytes| crate::json_value::parse(&bytes));
    let resource = observed_resource(event)?;
    let mut owners = BTreeSet::new();
    for rule in crate::replay::native_response_selected(policy, method, uri.path(), body.as_ref()) {
        let selected = &rule.rule.selector;
        let primary = selected
            .resource
            .as_ref()
            .is_some_and(|selected| resource_matches(selected, &resource))
            && selected
                .operation
                .as_ref()
                .is_none_or(|operation| operation == command)
            && selected.key.as_ref().is_none_or(|selector| {
                key_matches(selector, key) && key_matches(selector, target_key)
            });
        let owner = match &rule.rule.effect {
            NativeEffect::RedisSequence(effect) => {
                primary
                    && effect
                        .commands
                        .iter()
                        .any(|entry| entry.operation == command)
                    && effect.key.as_ref().is_some_and(|key| {
                        matches!(
                            &key.contract,
                            NativeKeyContract::Capture { .. }
                                | NativeKeyContract::Reference(_)
                                | NativeKeyContract::TimeWindow { .. }
                        )
                    })
            }
            NativeEffect::Identity(effect) => effect
                .references
                .iter()
                .any(|reference| resource_matches(&reference.contract.resource, &resource)),
            _ => false,
        };
        if owner {
            owners.insert(rule.rule.id.clone());
        }
    }
    Ok(owners)
}

fn resource_matches(selected: &crate::policy::Resource, actual: &crate::policy::Resource) -> bool {
    selected.protocol == actual.protocol
        && selected
            .endpoint
            .host
            .eq_ignore_ascii_case(&actual.endpoint.host)
        && selected.endpoint.port == actual.endpoint.port
        && selected
            .database
            .as_ref()
            .is_none_or(|database| Some(database) == actual.database.as_ref())
        && selected
            .username
            .as_ref()
            .is_none_or(|username| Some(username) == actual.username.as_ref())
}

fn key_matches(selector: &NativeKeySelector, key: &[u8]) -> bool {
    match selector {
        NativeKeySelector::Exact { value } => key == value.as_bytes(),
        NativeKeySelector::Affix { prefix, suffix } => {
            key.starts_with(prefix.as_bytes()) && key.ends_with(suffix.as_bytes())
        }
        NativeKeySelector::Numeric { prefix, suffix } => key
            .strip_prefix(prefix.as_bytes())
            .and_then(|value| value.strip_suffix(suffix.as_bytes()))
            .is_some_and(|value| !value.is_empty() && value.iter().all(u8::is_ascii_digit)),
    }
}

/// A protected witness candidate must describe the same physical operation.
/// Distinct keys are unrelated unless an existing native key owner establishes
/// an eligible translated key. Payloads, TTLs and options never select a pair.
pub(super) fn related_candidate(
    event: &Value,
    source: &[u8],
    target: &[u8],
    policy: &CompiledPolicy,
    request: &Value,
) -> Result<bool> {
    let command = event["command"]
        .as_str()
        .context("Redis candidate command unavailable")?;
    let source: Vec<Vec<u8>> = serde_json::from_slice(source)?;
    let target: Vec<Vec<u8>> = serde_json::from_slice(target)?;
    if command == "PUBLISH" {
        return Ok(source.first() == target.first());
    }
    let before = crate::replay::redis_field_values(command, &source, None)?;
    // A malformed same-operation candidate stays visible to the strict owner.
    let Ok(after) = crate::replay::redis_field_values(command, &target, None) else {
        return Ok(true);
    };
    if before.len() != after.len() {
        return Ok(true);
    }
    for (before, after) in before.iter().zip(&after) {
        if before.hash_field != after.hash_field || before.container != after.container {
            return Ok(false);
        }
        if before.key != after.key
            && native_key_owners(policy, Some(request), event, before.key, after.key, command)?
                .is_empty()
        {
            return Ok(false);
        }
    }
    Ok(true)
}
