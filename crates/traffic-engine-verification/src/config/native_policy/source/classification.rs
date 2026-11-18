use super::*;
use crate::config::process_owned_dependencies::BackgroundDependencyRuleConfig;
use crate::policy::Surface;
use serde_json::Value;

pub(super) fn validate(
    scope: &NativeSourceScope<'_>,
    compiled: &CompiledNativeRule,
    files: &[PathBuf],
    artifacts: &mut BTreeSet<PathBuf>,
) -> Result<usize> {
    if let n::NativeEffect::ProcessOwned(effect) = &compiled.rule.effect {
        ensure!(
            effect.source_revision.is_empty() || effect.source_revision == scope.source_revision,
            "ownership Source revision differs from the immutable snapshot"
        );
    }
    let projection = project_source_policy(std::slice::from_ref(compiled))?;
    let rule = projection
        .process_owned_dependencies
        .first()
        .context("Source ownership projection is missing")?;
    let context = project_source_policy(scope.policy_rules)?;
    let origins = crate::api_trigger::load(scope.case_source, &context.process_owned_dependencies)?;
    let mut ports = BTreeMap::new();
    if let BackgroundDependencyRuleConfig::Memcached {
        name,
        breeze_identity,
        ..
    } = rule
    {
        let directory = Path::new(crate::breeze::SOCKS_DIR);
        let descriptor = crate::breeze::resolve_identity(directory, breeze_identity)?;
        ports.insert(name.clone(), BTreeSet::from([descriptor.port]));
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                artifacts.insert(entry.path());
            }
        }
    }
    let mut count = 0;
    let mut subscriptions = BTreeMap::new();
    if matches!(rule, BackgroundDependencyRuleConfig::RedisPubsub { .. }) {
        each_event(
            files,
            |_, event| {
                Ok(
                    crate::config::process_owned_dependencies::pubsub::subscription_identity(event)
                        .is_some(),
                )
            },
            |_, _, event| {
                let id =
                    crate::config::process_owned_dependencies::pubsub::subscription_identity(event)
                        .expect("selected subscription");
                if let Some(before) = subscriptions.insert(id, event.clone()) {
                    ensure!(
                        before == *event,
                        "Source Pub/Sub subscription anchor is ambiguous"
                    );
                }
                Ok(())
            },
        )?;
    }
    let event_kind = match rule {
        BackgroundDependencyRuleConfig::Mysql { .. } => "mysql_exchange",
        BackgroundDependencyRuleConfig::Redis { .. }
        | BackgroundDependencyRuleConfig::RedisPublish { .. } => "redis_exchange",
        BackgroundDependencyRuleConfig::RedisPubsub { .. } => "redis_pub_sub_push",
        BackgroundDependencyRuleConfig::Http { .. } => "http_exchange",
        BackgroundDependencyRuleConfig::Memcached { .. } => "memcached_exchange",
        BackgroundDependencyRuleConfig::Motan { .. } => "motan_exchange",
    };
    each_event(
        files,
        |role, event| {
            if event["_source_proof_requires_original"] == true
                || event_kind == "redis_pub_sub_push"
            {
                // Oversized selector fields require a conservative original
                // read. Complete metadata retains origin wire identity and
                // SQL fingerprints; the original event still decides ownership.
                return Ok(event["event_type"] == event_kind);
            }
            if let BackgroundDependencyRuleConfig::RedisPublish { selector, .. } = rule {
                // Compact metadata has request selectors. Confirm the integer
                // reply from the original record before authorizing ownership.
                return Ok(selector.matches_recorded_request(event));
            }
            crate::protocols::replay::report::ownership::source_owned_match(
                event,
                role.case_id(),
                rule,
                &ports,
                &origins,
            )
        },
        |path, role, event| {
            if !crate::protocols::replay::report::ownership::source_owned_match(
                event,
                role.case_id(),
                rule,
                &ports,
                &origins,
            )? {
                return Ok(());
            }
            match event["event_type"].as_str() {
                Some("redis_pub_sub_push") => {
                    ensure!(
                        event["replay_safe"] == true && event["rpc_request"].is_null(),
                        "process-owned Pub/Sub input requires complete non-RPC notification evidence"
                    );
                    let raw = crate::config::process_owned_dependencies::pubsub::capture(
                        &event["response"],
                    )
                    .context("Source Pub/Sub input is unavailable")?;
                    ensure!(
                        crate::redis::parse_pubsub_push(&raw)?.is_some(),
                        "Source Pub/Sub notification framing is invalid"
                    );
                    let BackgroundDependencyRuleConfig::RedisPubsub { selector, .. } = rule else {
                        unreachable!("Pub/Sub selector")
                    };
                    let anchor = crate::config::process_owned_dependencies::pubsub::anchor(event)
                        .context("Source Pub/Sub input anchor is invalid")?;
                    crate::config::process_owned_dependencies::pubsub::validate_subscription(
                        selector,
                        event,
                        subscriptions.get(&anchor).context(
                            "Source Pub/Sub input has no original subscription confirmation",
                        )?,
                    )?;
                }
                Some("http_exchange") => {
                    crate::protocols::replay::http_source_witness(
                        event,
                        Surface::DependencyRequest,
                        path,
                    )?;
                    // Ownership cannot hide an incomplete or failed dependency.
                    ensure!(
                        event["error"].is_null() && event["response_status"].is_u64(),
                        "Source-owned HTTP response is failed or incomplete"
                    );
                    crate::protocols::replay::http_source_witness(
                        event,
                        Surface::DependencyResponse,
                        path,
                    )?;
                }
                Some("mysql_exchange") => {
                    crate::protocols::replay::mysql_source_witness(
                        event,
                        Surface::DependencyResponse,
                    )?;
                    ensure!(
                        event["outcome"] == "response"
                            && event["parse_warnings"]
                                .as_array()
                                .is_some_and(Vec::is_empty),
                        "Source-owned MySQL exchange is failed or has parse warnings"
                    );
                    if event["response"]["status"] == "ok" {
                        ensure!(
                            rule.trigger_source().is_some(),
                            "ordinary ownership only authorizes complete read results"
                        );
                    } else {
                        ensure!(
                    crate::config::process_owned_dependencies::mysql::evidence::complete_response(
                        event
                    ),
                    "Source-owned MySQL read requires complete immutable row metadata"
                );
                    }
                }
                Some("redis_exchange" | "memcached_exchange" | "motan_exchange") => {
                    ensure!(
                        event["replay_safe"] == true && event["outcome"] == "response",
                        "Source-owned exchange is unsafe or incomplete"
                    );
                    if matches!(
                        rule,
                        BackgroundDependencyRuleConfig::Redis { .. }
                            | BackgroundDependencyRuleConfig::RedisPublish { .. }
                    ) && !rule.uses_redis_snapshot()
                    {
                        ensure!(
                            event["cache_snapshot_rule"].is_null()
                                && event["cache_snapshot_hit"] != true,
                            "finite process-owned Redis work requires original single-use evidence, not snapshot seeds or hits"
                        );
                    }
                    complete_captures(event)?;
                    validate_native_frames(event)?;
                }
                _ => (),
            }
            count += 1;
            Ok(())
        },
    )?;
    ensure!(
        count > 0,
        "Source ownership selector has no complete immutable dependency evidence"
    );
    Ok(count)
}

fn complete_captures(value: &Value) -> Result<()> {
    match value {
        Value::Object(fields) => {
            if fields.contains_key("encoding") && fields.contains_key("data") {
                ensure!(
                    fields.get("truncated") != Some(&Value::Bool(true)),
                    "Source ownership capture is truncated"
                );
                let decoded = crate::api_trigger::decode(value)
                    .context("Source ownership capture is invalid")?;
                for name in ["original_len", "stored_len"] {
                    ensure!(
                        fields
                            .get(name)
                            .is_none_or(|length| length.as_u64() == Some(decoded.len() as u64)),
                        "Source ownership capture length is inconsistent"
                    );
                }
            }
            for value in fields.values() {
                complete_captures(value)?;
            }
        }
        Value::Array(items) => {
            for value in items {
                complete_captures(value)?;
            }
        }
        _ => (),
    }
    Ok(())
}

fn validate_native_frames(event: &Value) -> Result<()> {
    match event["event_type"].as_str() {
        Some("redis_exchange") => {
            let response = crate::api_trigger::decode(&event["response"])
                .context("Source Redis response is unavailable")?;
            crate::redis::frame_kind(&bytes::Bytes::from(response))?;
        }
        Some("memcached_exchange") => {
            anyhow::bail!("Memcached recording has no installed protocol implementation");
        }
        Some("motan_exchange") => {
            anyhow::bail!("Motan recording has no installed protocol implementation");
        }
        #[cfg(any())]
        Some("motan_exchange") => {
            ensure!(
                event["parse_warnings"]
                    .as_array()
                    .is_some_and(Vec::is_empty),
                "Source Motan parse warnings prevent ownership proof"
            );
            let request = crate::motan::Frame::decode(
                crate::api_trigger::decode(&event["request"])
                    .context("Source Motan request is unavailable")?,
            )?;
            let response = crate::motan::Frame::decode(
                crate::api_trigger::decode(&event["response"])
                    .context("Source Motan response is unavailable")?,
            )?;
            ensure!(
                request.request && !response.request && request.request_id == response.request_id,
                "Source Motan request/response framing or correlation differs"
            );
            let identity = request.request_metadata()?;
            ensure!(
                identity.group.as_deref() == event["group"].as_str()
                    && identity.identity.interface_name.as_deref()
                        == event["interface_name"].as_str()
                    && identity.identity.method_name.as_deref() == event["method_name"].as_str(),
                "Source Motan semantic selector differs from its complete native request"
            );
        }
        _ => (),
    }
    Ok(())
}
