//! Validation of finite Redis process selectors, separate from live matching.
use super::*;

pub(super) fn validate(rule: &BackgroundDependencyRuleConfig) -> Result<()> {
    let BackgroundDependencyRuleConfig::Redis {
        ports,
        command,
        keys,
        key_patterns,
        key_prefix,
        key_suffix,
        initial_load_timeout_ms,
        fields,
        source_revision,
        source_evidence,
        ..
    } = rule
    else {
        unreachable!("Redis process selector")
    };
    let name = rule.name();
    validate_redis_ports(name, ports)?;
    if rule.trigger_source().is_some() {
        crate::config::api_trigger::validate_redis(rule)?;
        if !source_revision.is_empty() {
            validate_source_revision(source_revision)?;
        }
        validate_optional_source_evidence(source_evidence)?;
        return Ok(());
    }
    if let BackgroundDependencyRuleConfig::Redis {
        key_templates,
        arguments,
        key_sequence,
        script,
        ..
    } = rule
    {
        anyhow::ensure!(
            key_templates.is_empty()
                && arguments.is_empty()
                && key_sequence.is_empty()
                && script.is_none(),
            "key_templates and arguments require trigger_source"
        );
    }
    match command.as_str() {
        "SET" => {
            anyhow::ensure!(
                initial_load_timeout_ms.is_none()
                    && key_patterns.is_empty()
                    && key_prefix.is_empty()
                    && key_suffix.is_empty()
                    && fields.is_empty(),
                "finite process-owned Redis SET requires exact keys and cannot be a reusable snapshot"
            );
            validate_exact_redis_keys(name, command, keys)?;
        }
        "ZCOUNT" => {
            if !keys.is_empty()
                || !key_patterns.is_empty()
                || initial_load_timeout_ms.is_some()
                || !fields.is_empty()
            {
                bail!(
                    "Redis ZCOUNT process-owned dependency rule {name:?} must use key_prefix/key_suffix without keys or initial_load_timeout_ms"
                );
            }
            validate_single_line("Redis process-owned dependency key prefix", key_prefix, 512)?;
            validate_single_line("Redis process-owned dependency key suffix", key_suffix, 512)?;
        }
        "GET" | "SCARD" | "HGETALL" => {
            if !key_patterns.is_empty()
                || !key_prefix.is_empty()
                || !key_suffix.is_empty()
                || !fields.is_empty()
            {
                bail!(
                    "Redis {command} process-owned dependency rule {name:?} must use exact keys instead of key_prefix/key_suffix"
                );
            }
            validate_exact_redis_keys(name, command, keys)?;
            if *initial_load_timeout_ms == Some(0) {
                bail!(
                    "Redis {command} process-owned dependency rule {name:?} initial_load_timeout_ms must be greater than zero"
                );
            }
        }
        "HGET" | "HMGET" | "HSCAN" => {
            if !key_prefix.is_empty() || !key_suffix.is_empty() {
                bail!(
                    "Redis {command} process-owned dependency rule {name:?} must use keys/key_patterns instead of key_prefix/key_suffix"
                );
            }
            if *initial_load_timeout_ms == Some(0)
                || initial_load_timeout_ms.is_some()
                    && (keys.is_empty() || !key_patterns.is_empty())
            {
                bail!(
                    "Redis {command} process-owned dependency rule {name:?} initial_load_timeout_ms requires a positive timeout and exact initial-load keys"
                );
            }
            validate_redis_key_selectors(name, command, keys, key_patterns)?;
            if command == "HSCAN" {
                if !fields.is_empty() {
                    bail!("Redis HSCAN process-owned dependency rule {name:?} must not use fields");
                }
            } else {
                validate_redis_hash_fields(name, command, fields)?;
            }
        }
        _ => bail!(
            "Redis process-owned dependency rule {name:?} currently supports only commands \"SET\", \"ZCOUNT\", \"GET\", \"SCARD\", \"HGETALL\", \"HGET\", \"HMGET\", and \"HSCAN\""
        ),
    }
    if !source_revision.is_empty() {
        validate_source_revision(source_revision)?;
    }
    validate_optional_source_evidence(source_evidence)?;
    Ok(())
}
