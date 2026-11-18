//! Source selector verification and read-only dependency evidence refresh.
//! Ownership changes are independently proved in dependency_review; actual
//! Replay reports never move unused observations into another owner's pool.
#[cfg(any(test, feature = "test-support"))]
use super::evidence::build_dependency_evidence;
use crate::config::BackgroundDependencyRuleConfig;
#[cfg(any(test, feature = "test-support"))]
use crate::config::SourceTrafficPolicyConfig;
use crate::config::process_owned_dependencies::redis_rule_matches;
#[cfg(any(test, feature = "test-support"))]
use crate::replay::report::dependency_evidence_path;
use anyhow::Result;
#[cfg(any(test, feature = "test-support"))]
use anyhow::ensure;
use base64::{Engine as _, engine::general_purpose::STANDARD};
#[cfg(any(test, feature = "test-support"))]
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(any(test, feature = "test-support"))]
use std::fs;
#[cfg(any(test, feature = "test-support"))]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize)]
#[cfg(any(test, feature = "test-support"))]
pub struct BackgroundReclassification {
    pub rules_fingerprint: String,
    pub matched_unused_case: usize,
    pub by_protocol: BTreeMap<String, usize>,
    pub remaining_dirty_case_ids: BTreeSet<String>,
}

pub fn parse_background_dependency_evidence<T: DeserializeOwned>(
    raw: &str,
) -> serde_json::Result<T> {
    serde_json::from_str(raw)
}

#[cfg(any(test, feature = "test-support"))]
pub fn reclassify_background_dependencies(
    policy: &Path,
    report_path: &Path,
    cases: &BTreeMap<String, PathBuf>,
) -> Result<BackgroundReclassification> {
    let mut report: Value = serde_json::from_slice(&fs::read(report_path)?)?;
    reclassify_background_report(policy, report_path, &mut report, cases)
}

#[cfg(any(test, feature = "test-support"))]
pub fn reclassify_background_report(
    policy: &Path,
    report_path: &Path,
    report: &mut Value,
    _cases: &BTreeMap<String, PathBuf>,
) -> Result<BackgroundReclassification> {
    ensure!(
        report["version"] == 7,
        "dependency evidence refresh requires current Replay report version 7"
    );
    let (_, fingerprints) = SourceTrafficPolicyConfig::load_with_fingerprints(policy)?;
    let evidence = build_dependency_evidence(report);
    let path = dependency_evidence_path(report_path);
    let payload = serde_json::to_vec_pretty(&evidence)?;
    if path.exists() {
        crate::config::edit::write_atomic(&path, &payload)?;
    } else {
        crate::config::edit::create_atomic(&path, &payload)?;
    }
    Ok(BackgroundReclassification {
        rules_fingerprint: fingerprints.classification,
        remaining_dirty_case_ids: dirty_case_ids(report),
        ..Default::default()
    })
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
    Ok(matching_rule(event, std::slice::from_ref(rule), memcached_ports).is_some())
}

fn matching_rule<'a>(
    event: &Value,
    rules: &'a [BackgroundDependencyRuleConfig],
    memcached_ports: &BTreeMap<String, BTreeSet<u16>>,
) -> Option<&'a str> {
    rules.iter().find_map(|rule| {
        let matches = match rule {
            BackgroundDependencyRuleConfig::RedisPubsub { selector, .. } => {
                crate::config::process_owned_dependencies::pubsub::matches_value(selector, event)
            }
            BackgroundDependencyRuleConfig::RedisPublish { selector, .. } => {
                selector.matches_recorded_request(event)
                    && crate::config::process_owned_dependencies::publish::successful_record(event)
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
            | BackgroundDependencyRuleConfig::Mysql { .. } => false,
        };
        matches.then(|| rule.name())
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

#[cfg(any(test, feature = "test-support"))]
fn dirty_case_ids(report: &Value) -> BTreeSet<String> {
    let mut case_ids = BTreeSet::new();
    for field in [
        "case_execution_failures",
        "unmatched_queries",
        "unsupported_commands",
        "unused_case_exchanges",
        "unmatched_http_requests",
        "unsupported_http_exchanges",
        "http_request_header_mismatches",
        "dependency_pre_matches",
        "unused_case_http_exchanges",
    ] {
        collect_case_ids(report, field, &mut case_ids);
    }
    for protocol in ["redis", "memcached", "kafka", "motan"] {
        let Some(protocol_report) = report.get(protocol) else {
            continue;
        };
        for field in ["unmatched", "unsupported", "unsafe_events", "unused_case"] {
            collect_case_ids(protocol_report, field, &mut case_ids);
        }
    }
    case_ids
}

#[cfg(any(test, feature = "test-support"))]
fn collect_case_ids(report: &Value, field: &str, output: &mut BTreeSet<String>) {
    let Some(events) = report.get(field).and_then(Value::as_array) else {
        return;
    };
    output.extend(
        events
            .iter()
            .filter_map(|event| event.get("case_id").and_then(Value::as_str))
            .map(ToOwned::to_owned),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn refresh_preserves_actual_report_and_does_not_waive_unused_ownership() {
        let temp = tempfile::tempdir().unwrap();
        let policy = temp.path().join("policy.yaml");
        fs::write(
            &policy,
            crate::config::native_policy::empty_policy().unwrap(),
        )
        .unwrap();
        let path = temp.path().join("replay.json");
        let mut report = json!({"version":7,"cases":[{"case_id":"a"}],
            "unused_case_http_exchanges":[{"case_id":"a","index":0,"method":"GET","uri":"/task"}]});
        let bytes = serde_json::to_vec(&report).unwrap();
        fs::write(&path, &bytes).unwrap();
        let result =
            reclassify_background_report(&policy, &path, &mut report, &BTreeMap::new()).unwrap();
        assert_eq!(result.matched_unused_case, 0);
        assert!(result.remaining_dirty_case_ids.contains("a"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(serde_json::to_vec(&report).unwrap(), bytes);
    }

    #[test]
    fn previous_report_generation_is_rejected_without_owner_migration() {
        let mut report = serde_json::json!({"version":6});
        assert!(
            reclassify_background_report(
                Path::new("missing"),
                Path::new("missing"),
                &mut report,
                &BTreeMap::new()
            )
            .is_err()
        );
    }
}
