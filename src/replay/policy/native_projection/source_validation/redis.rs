use super::*;
use crate::policy::Database;
use crate::replay::policy::request_contract::RedisRequestContext;
use crate::replay::{ReplaySource, TargetKey};

pub(super) fn register_callbacks(
    state: &mut crate::replay::redis::RedisReplayState,
    case: &NativeSourceCase<'_>,
) -> Result<()> {
    // JSONL completion order can place an ACK after its PUBLISH. Link the
    // original finite callback evidence before validating request contracts.
    for event in case.events.iter().filter(|event| {
        event["event_type"] == "redis_pub_sub_push" && event["rpc_request"].is_object()
    }) {
        state.pubsub.register(
            serde_json::from_value(event.clone())?,
            ReplaySource::Case,
            Some(case.id),
        )?;
    }
    Ok(())
}

pub(super) fn validate(
    runtime: &mut ReplayPolicyRuntime,
    state: &mut crate::replay::redis::RedisReplayState,
    targets: &mut BTreeMap<TargetKey, crate::replay::ReplayTarget>,
    case: &NativeSourceCase<'_>,
    event: &Value,
    coverage: &mut super::coverage::Coverage,
) -> Result<()> {
    let target = TargetKey {
        host: event["target_host"]
            .as_str()
            .context("Source Redis endpoint is missing")?
            .into(),
        port: u16::try_from(
            event["target_port"]
                .as_u64()
                .context("Source Redis port is missing")?,
        )?,
    };
    let database = event["database"].as_i64().unwrap_or(0);
    let username = event["username"].as_str();
    let selected = runtime
        .request_contracts
        .compiled_rules()
        .is_some_and(|compiled| {
            compiled.native.iter().any(|rule| {
                if !matches!(
                    rule.rule.effect,
                    NativeEffect::Identity(_)
                        | NativeEffect::RedisSequence(_)
                        | NativeEffect::RedisLock
                        | NativeEffect::RedisPublishIdentity(_)
                ) {
                    return false;
                }
                let guard = NativeScopeGuard::from_rule(&rule.rule);
                guard.matches_case(
                    case.request["method"].as_str().unwrap_or_default(),
                    &super::super::super::pattern::uri_path(
                        case.request["uri"].as_str().unwrap_or_default(),
                    ),
                    super::super::super::case_condition::request_body(case.request).as_ref(),
                ) && (guard.matches_capture_resource(
                    crate::policy::Protocol::Redis,
                    &target,
                    Some(&Database::Index(database)),
                    username,
                ) || guard.matches_reference_resource(
                    crate::policy::Protocol::Redis,
                    &target,
                    Some(&Database::Index(database)),
                    username,
                ))
            })
        });
    if !selected {
        return Ok(());
    }
    let record = serde_json::from_value(event.clone())?;
    state.register_exchange(record, ReplaySource::Case, Some(case.id), targets, &[])?;
    let args = event["args"]
        .as_array()
        .context("Source Redis args are missing")?
        .iter()
        .map(|value| {
            crate::api_trigger::decode(value)
                .context("Source Redis argument is invalid or truncated")
        })
        .collect::<Result<Vec<_>>>()?;
    let command = event["command"]
        .as_str()
        .context("Source Redis command is missing")?;
    coverage.references(
        runtime
            .dynamic_values
            .source_redis_references(case.id, &target, database, username, command, &args),
    );
    if let Some(normalized) = runtime.dynamic_values.redis_with_identity(
        Some(case.id),
        &target,
        super::super::super::dynamic_values::RedisIdentity { database, username },
        command,
        &args,
        &args,
    ) {
        let normalized = normalized?;
        ensure!(
            normalized.source == normalized.actual,
            "Source identity self validation changed values"
        );
        runtime.dynamic_values.commit(case.id, normalized.decision);
    }
    let clock = started(event)?;
    let context = RedisRequestContext {
        observation_id: None,
        case: case.id,
        target: &target,
        database,
        username,
        command,
        recorded_at: clock,
        actual_at: clock,
        connection_id: event["connection_id"]
            .as_str()
            .map(str::parse)
            .transpose()?,
        sequence: event["sequence"].as_u64(),
    };
    if let Some(decision) = runtime
        .request_contracts
        .preview_redis_context(&context, &args, &args)
    {
        runtime.request_contracts.commit(decision?);
    }
    Ok(())
}
