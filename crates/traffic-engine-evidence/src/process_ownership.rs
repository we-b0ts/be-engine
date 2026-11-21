//! Match authenticated Source events against prepared process ownership selectors.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;

use crate::config::{
    BackgroundDependencyRuleConfig, process_owned_dependencies::redis_rule_matches,
};

pub fn resolved_memcached_ports(
    rules: &[BackgroundDependencyRuleConfig],
) -> Result<BTreeMap<String, BTreeSet<u16>>> {
    let directory = Path::new(traffic_engine_config::breeze::SOCKS_DIR);
    let mut ports = BTreeMap::new();
    for rule in rules {
        if let BackgroundDependencyRuleConfig::Memcached {
            name,
            breeze_identity,
            ..
        } = rule
            && let Some(descriptor) =
                traffic_engine_config::breeze::try_resolve_identity(directory, breeze_identity)?
        {
            ports.insert(name.clone(), BTreeSet::from([descriptor.port]));
        }
    }
    Ok(ports)
}

pub fn needs_original(rule: &BackgroundDependencyRuleConfig, event: &Value) -> bool {
    let Some(event_type) = event["event_type"].as_str() else {
        return false;
    };
    let missing_facts = event["_source_proof_requires_original"] == true;
    if let Some(selector) = rule.finite_request() {
        return selector.event_types().contains(&event_type)
            && (missing_facts || selector.matches_request(event));
    }
    match rule {
        BackgroundDependencyRuleConfig::Mysql { .. } => {
            missing_facts && event_type == "mysql_exchange"
        }
        BackgroundDependencyRuleConfig::Redis { .. } => {
            missing_facts && event_type == "redis_exchange"
        }
        BackgroundDependencyRuleConfig::RedisPubsub { .. } => event_type == "redis_pub_sub_push",
        BackgroundDependencyRuleConfig::Http { .. } => {
            missing_facts && event_type == "http_exchange"
        }
        BackgroundDependencyRuleConfig::Memcached { .. } => {
            missing_facts && event_type == "memcached_exchange"
        }
        BackgroundDependencyRuleConfig::Motan { .. } => {
            missing_facts && event_type == "motan_exchange"
        }
        _ => false,
    }
}

pub fn source_owned_match(
    event: &Value,
    case: Option<&str>,
    rule: &BackgroundDependencyRuleConfig,
    memcached_ports: &BTreeMap<String, BTreeSet<u16>>,
    origins: &crate::api_trigger::OriginIndex,
) -> Result<bool> {
    if rule.trigger_source().is_some() {
        return Ok(case
            .and_then(|case| origins.witness(case, event))
            .is_some_and(|witness| witness.rule == rule.name()));
    }
    if let BackgroundDependencyRuleConfig::Mysql { selector, .. } = rule {
        return Ok(event["event_type"] == "mysql_exchange"
            && selector.matches_query(
                event["target_host"].as_str(),
                event["target_port"]
                    .as_u64()
                    .and_then(|p| u16::try_from(p).ok()),
                event["database"].as_str(),
                event["username"].as_str(),
                event["command"].as_str().unwrap_or_default(),
                event["sql"].as_str(),
            ));
    }
    if matches!(rule, BackgroundDependencyRuleConfig::Http { .. }) {
        let matched = event["event_type"] == "http_exchange"
            && event["method"]
                .as_str()
                .zip(event["uri"].as_str())
                .is_some_and(|(method, uri)| {
                    uri.parse::<hyper::Uri>().is_ok_and(|uri| {
                        rule.matches_http_request(method, &uri, event["authority"].as_str())
                    })
                });
        return Ok(matched);
    }
    if let Some(selector) = rule.finite_request() {
        return selector.matches_evidence(event);
    }
    Ok(match rule {
        BackgroundDependencyRuleConfig::RedisPubsub { selector, .. } => {
            crate::config::process_owned_dependencies::pubsub::matches_value(selector, event)
        }
        BackgroundDependencyRuleConfig::Redis { .. } => redis_event_matches_rule(event, rule),
        BackgroundDependencyRuleConfig::Memcached {
            name,
            command,
            key_start,
            key_end,
            key_separator,
            key_suffix,
            ..
        } => {
            event.get("event_type").and_then(Value::as_str) == Some("memcached_exchange")
                && event.get("replay_safe").and_then(Value::as_bool) == Some(true)
                && event
                    .get("target_port")
                    .and_then(Value::as_u64)
                    .and_then(|port| u16::try_from(port).ok())
                    .is_some_and(|port| {
                        memcached_ports
                            .get(name)
                            .is_some_and(|ports| ports.contains(&port))
                    })
                && event
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(command))
                && event
                    .get("key")
                    .and_then(decode_capture)
                    .is_some_and(|key| {
                        crate::config::process_owned_dependencies::matches_memcached_key_series(
                            &key,
                            *key_start,
                            *key_end,
                            key_separator.as_bytes()[0],
                            key_suffix.as_bytes(),
                        )
                    })
        }
        BackgroundDependencyRuleConfig::Motan {
            group,
            interface_name,
            method_name,
            ..
        } => {
            event.get("event_type").and_then(Value::as_str) == Some("motan_exchange")
                && event.get("heartbeat").and_then(Value::as_bool) != Some(true)
                && event.get("group").and_then(Value::as_str) == Some(group)
                && event.get("interface_name").and_then(Value::as_str) == Some(interface_name)
                && event.get("method_name").and_then(Value::as_str) == Some(method_name)
        }
        BackgroundDependencyRuleConfig::Http { .. }
        | BackgroundDependencyRuleConfig::Mysql { .. }
        | BackgroundDependencyRuleConfig::RedisPublish { .. }
        | BackgroundDependencyRuleConfig::RedisScript { .. } => false,
    })
}

fn redis_event_matches_rule(event: &Value, rule: &BackgroundDependencyRuleConfig) -> bool {
    if event.get("event_type").and_then(Value::as_str) != Some("redis_exchange")
        || event
            .get("session_setup")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || event.get("replay_safe").and_then(Value::as_bool) != Some(true)
    {
        return false;
    }
    let Some(target_port) = event
        .get("target_port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
    else {
        return false;
    };
    let Some(command) = event.get("command").and_then(Value::as_str) else {
        return false;
    };
    let Some(args) = event
        .get("args")
        .and_then(Value::as_array)
        .and_then(|args| args.iter().map(decode_capture).collect::<Option<Vec<_>>>())
    else {
        return false;
    };
    redis_rule_matches(rule, target_port, command, &args)
}

fn decode_capture(value: &Value) -> Option<Vec<u8>> {
    if value.get("truncated").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    let data = value.get("data").and_then(Value::as_str)?;
    match value.get("encoding").and_then(Value::as_str)? {
        "utf8" => Some(data.as_bytes().to_vec()),
        "base64" => STANDARD.decode(data.as_bytes()).ok(),
        _ => None,
    }
}
