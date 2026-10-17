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
    each_event(files, |path, role, event| {
        if !crate::replay::source_owned_match(event, role.case_id(), rule, &ports, &origins)? {
            return Ok(());
        }
        match event["event_type"].as_str() {
            Some("http_exchange") => {
                crate::replay::http_source_witness(event, Surface::DependencyRequest, path)?;
                // Ownership cannot hide an incomplete or failed dependency.
                ensure!(
                    event["error"].is_null() && event["response_status"].is_u64(),
                    "Source-owned HTTP response is failed or incomplete"
                );
                crate::replay::http_source_witness(event, Surface::DependencyResponse, path)?;
            }
            Some("mysql_exchange") => {
                crate::replay::mysql_source_witness(event, Surface::DependencyResponse)?;
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
                complete_captures(event)?;
                validate_native_frames(event)?;
            }
            _ => (),
        }
        count += 1;
        Ok(())
    })?;
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
            let envelope =
                crate::replay::memcached_source_witness(event, Surface::DependencyResponse)?;
            crate::memcached::value_slot::witness_values(&envelope, true)?;
        }
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
