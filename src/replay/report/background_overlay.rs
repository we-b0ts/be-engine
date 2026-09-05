use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hyper::Uri;
use serde::Serialize;
use serde_json::{Value, json};

use super::dependency_evidence::{build_dependency_evidence, dependency_evidence_path};
use crate::config::process_owned_dependencies::redis_rule_matches;
use crate::config::{BackgroundDependencyRuleConfig, SourceTrafficPolicyConfig};
use crate::recorder::background::BackgroundDependencyMatcher;

mod mysql;

const ORIGINAL_CASE_ID: &str = "background_original_case_id";
const MATCHED_RULE: &str = "background_rule";

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct BackgroundReclassification {
    pub rules_fingerprint: String,
    pub matched_unused_case: usize,
    pub by_protocol: BTreeMap<String, usize>,
    pub remaining_dirty_case_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExchangeIdentity {
    protocol: String,
    case_id: String,
    connection_id: String,
    sequence: u64,
}

pub(crate) fn reclassify_background_dependencies(
    source_traffic_policy: &Path,
    report_path: &Path,
    case_dirs: &BTreeMap<String, PathBuf>,
) -> Result<BackgroundReclassification> {
    let config = SourceTrafficPolicyConfig::load(source_traffic_policy)?;
    let rules = &config.process_owned_dependencies;
    let matcher = BackgroundDependencyMatcher::from_rules(rules)?;
    let memcached_ports = matcher.resolved_memcached_rule_ports();
    let mut matched = matched_recorded_exchanges(case_dirs, rules, &memcached_ports)?;
    let payload = fs::read(report_path)
        .with_context(|| format!("failed to read replay report {}", report_path.display()))?;
    let mut report: Value = serde_json::from_slice(&payload)
        .with_context(|| format!("invalid replay report JSON {}", report_path.display()))?;
    restore_previous_reclassification(&mut report);

    let mut by_protocol = BTreeMap::new();
    mysql::reclassify(&mut report, rules, &mut matched.mysql, &mut by_protocol);
    reclassify_http(&mut report, rules, &mut by_protocol);
    for protocol in ["redis", "memcached", "motan"] {
        reclassify_command_protocol(&mut report, protocol, &matched.commands, &mut by_protocol);
    }
    by_protocol.retain(|_, count| *count > 0);
    let matched_unused_case = by_protocol.values().sum();
    let rules_payload = serde_json::to_vec(rules)?;
    let rules_fingerprint = crate::verification_progress::fingerprint(&rules_payload);
    let remaining_dirty_case_ids = dirty_case_ids(&report);
    report["background_reclassification"] = json!({
        "rules_fingerprint": rules_fingerprint,
        "matched_unused_case": matched_unused_case,
        "by_protocol": by_protocol,
    });
    write_json_atomic(report_path, &report)?;
    let evidence = build_dependency_evidence(&report);
    write_json_atomic(&dependency_evidence_path(report_path), &evidence)?;
    Ok(BackgroundReclassification {
        rules_fingerprint,
        matched_unused_case,
        by_protocol,
        remaining_dirty_case_ids,
    })
}

#[derive(Default)]
struct RecordedMatches {
    commands: BTreeMap<ExchangeIdentity, String>,
    mysql: BTreeMap<String, Vec<Value>>,
}

fn matched_recorded_exchanges(
    case_dirs: &BTreeMap<String, PathBuf>,
    rules: &[BackgroundDependencyRuleConfig],
    memcached_ports: &BTreeMap<String, BTreeSet<u16>>,
) -> Result<RecordedMatches> {
    let mut matched = RecordedMatches::default();
    let has_mysql = rules
        .iter()
        .any(|rule| matches!(rule, BackgroundDependencyRuleConfig::Mysql { .. }));
    for (case_id, case_dir) in case_dirs {
        let path = case_dir.join("dependencies.jsonl");
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read case dependencies {}", path.display()))?;
        for (line_index, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line).with_context(|| {
                format!(
                    "invalid dependency JSON at {} line {}",
                    path.display(),
                    line_index + 1
                )
            })?;
            // Share the JSONL read with the command protocols. MySQL needs the
            // original SQL and complete response for fingerprint correlation.
            if has_mysql && value["event_type"] == "mysql_exchange" {
                matched
                    .mysql
                    .entry(case_id.clone())
                    .or_default()
                    .push(value);
                continue;
            }
            let Some(protocol) = dependency_protocol(&value) else {
                continue;
            };
            let Some(rule) = matching_rule(&value, rules, memcached_ports) else {
                continue;
            };
            let Some(connection_id) = value.get("connection_id").and_then(Value::as_str) else {
                continue;
            };
            let Some(sequence) = value.get("sequence").and_then(Value::as_u64) else {
                continue;
            };
            matched.commands.insert(
                ExchangeIdentity {
                    protocol: protocol.to_string(),
                    case_id: case_id.clone(),
                    connection_id: connection_id.to_string(),
                    sequence,
                },
                rule.to_string(),
            );
        }
    }
    Ok(matched)
}

fn matching_rule<'a>(
    event: &Value,
    rules: &'a [BackgroundDependencyRuleConfig],
    memcached_ports: &BTreeMap<String, BTreeSet<u16>>,
) -> Option<&'a str> {
    rules.iter().find_map(|rule| {
        let matches = match rule {
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

fn dependency_protocol(value: &Value) -> Option<&'static str> {
    match value.get("event_type").and_then(Value::as_str)? {
        "redis_exchange" => Some("redis"),
        "memcached_exchange" => Some("memcached"),
        "motan_exchange" => Some("motan"),
        _ => None,
    }
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

fn restore_previous_reclassification(report: &mut Value) {
    restore_array(report, "unused_global_exchanges", "unused_case_exchanges");
    restore_array(
        report,
        "unused_global_http_exchanges",
        "unused_case_http_exchanges",
    );
    for protocol in ["redis", "memcached", "motan"] {
        let Some(protocol_report) = report.get_mut(protocol) else {
            continue;
        };
        restore_array(protocol_report, "unused_global", "unused_case");
    }
}

fn restore_array(report: &mut Value, global_field: &str, case_field: &str) {
    let Some(object) = report.as_object_mut() else {
        return;
    };
    let mut global = object
        .remove(global_field)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let mut case = object
        .remove(case_field)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let mut retained = Vec::with_capacity(global.len());
    for mut event in global.drain(..) {
        let original_case = event
            .get(ORIGINAL_CASE_ID)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if let Some(original_case) = original_case {
            if let Some(event) = event.as_object_mut() {
                event.insert("case_id".to_string(), Value::String(original_case));
                event.insert("source".to_string(), Value::String("case".to_string()));
                event.remove(ORIGINAL_CASE_ID);
                event.remove(MATCHED_RULE);
            }
            case.push(event);
        } else {
            retained.push(event);
        }
    }
    object.insert(global_field.to_string(), Value::Array(retained));
    object.insert(case_field.to_string(), Value::Array(case));
}

fn reclassify_http(
    report: &mut Value,
    rules: &[BackgroundDependencyRuleConfig],
    counts: &mut BTreeMap<String, usize>,
) {
    move_matching_events(
        report,
        "unused_case_http_exchanges",
        "unused_global_http_exchanges",
        |event| matching_http_rule(event, rules),
        counts.entry("http".to_string()).or_default(),
    );
}

fn matching_http_rule<'a>(
    event: &Value,
    rules: &'a [BackgroundDependencyRuleConfig],
) -> Option<&'a str> {
    let method = event.get("method").and_then(Value::as_str)?;
    let uri = event.get("uri").and_then(Value::as_str)?;
    let authority = report_http_authority(event, uri)?;
    let path = uri
        .parse::<Uri>()
        .ok()
        .map(|uri| uri.path().to_string())
        .unwrap_or_else(|| uri.split('?').next().unwrap_or(uri).to_string());
    rules.iter().find_map(|rule| {
        let BackgroundDependencyRuleConfig::Http {
            authorities,
            methods,
            path_prefixes,
            ..
        } = rule
        else {
            return None;
        };
        (authorities
            .iter()
            .any(|candidate| normalize_authority(candidate).as_deref() == Some(&authority))
            && methods
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(method))
            && path_prefixes.iter().any(|prefix| path.starts_with(prefix)))
        .then(|| rule.name())
    })
}

fn report_http_authority(event: &Value, uri: &str) -> Option<String> {
    if let Some(authority) = uri
        .parse::<Uri>()
        .ok()
        .and_then(|uri| uri.authority().map(ToString::to_string))
        .and_then(|authority| normalize_authority(&authority))
    {
        return Some(authority);
    }
    let target = event.get("target")?;
    let host = target.get("host")?.as_str()?.to_ascii_lowercase();
    let port = target.get("port")?.as_u64()?;
    let scheme = event
        .get("scheme")
        .and_then(Value::as_str)
        .unwrap_or("http");
    if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        Some(host)
    } else {
        Some(format!("{host}:{port}"))
    }
}

fn normalize_authority(value: &str) -> Option<String> {
    let authority = value.parse::<hyper::http::uri::Authority>().ok()?;
    let host = authority.host().to_ascii_lowercase();
    Some(match authority.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn reclassify_command_protocol(
    report: &mut Value,
    protocol: &str,
    matched: &BTreeMap<ExchangeIdentity, String>,
    counts: &mut BTreeMap<String, usize>,
) {
    let Some(protocol_report) = report.get_mut(protocol) else {
        return;
    };
    move_matching_events(
        protocol_report,
        "unused_case",
        "unused_global",
        |event| {
            let identity = ExchangeIdentity {
                protocol: protocol.to_string(),
                case_id: event.get("case_id")?.as_str()?.to_string(),
                connection_id: event.get("connection_id")?.as_str()?.to_string(),
                sequence: event.get("sequence")?.as_u64()?,
            };
            matched.get(&identity).map(String::as_str)
        },
        counts.entry(protocol.to_string()).or_default(),
    );
}

fn move_matching_events<'a>(
    report: &mut Value,
    case_field: &str,
    global_field: &str,
    mut matching_rule: impl FnMut(&Value) -> Option<&'a str>,
    count: &mut usize,
) {
    let Some(object) = report.as_object_mut() else {
        return;
    };
    let mut case = object
        .remove(case_field)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let mut global = object
        .remove(global_field)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let mut retained = Vec::with_capacity(case.len());
    for mut event in case.drain(..) {
        // A bare ROLLBACK at request teardown is SQLAlchemy session-close
        // driver control traffic, not an application dependency the target
        // must reproduce; drop it from the dirty view.
        if is_session_control_exchange(&event) {
            continue;
        }
        let Some(rule) = matching_rule(&event).map(ToOwned::to_owned) else {
            retained.push(event);
            continue;
        };
        let original_case = event
            .get("case_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if let (Some(original_case), Some(event)) = (original_case, event.as_object_mut()) {
            event.insert("case_id".to_string(), Value::Null);
            event.insert("source".to_string(), Value::String("global".to_string()));
            event.insert(ORIGINAL_CASE_ID.to_string(), Value::String(original_case));
            event.insert(MATCHED_RULE.to_string(), Value::String(rule));
            global.push(Value::Object(event.clone()));
            *count += 1;
        } else {
            retained.push(event);
        }
    }
    object.insert(case_field.to_string(), Value::Array(retained));
    object.insert(global_field.to_string(), Value::Array(global));
}

fn dirty_case_ids(report: &Value) -> BTreeSet<String> {
    let mut case_ids = BTreeSet::new();
    for field in [
        "unmatched_queries",
        "unsupported_commands",
        "unused_case_exchanges",
        "unmatched_http_requests",
        "unsupported_http_exchanges",
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

/// Identifies recorded MySQL session-control traffic that the target is never
/// expected to reproduce: a bare ROLLBACK from driver/session teardown.
fn is_session_control_exchange(event: &Value) -> bool {
    event.get("command").and_then(Value::as_str) == Some("COM_QUERY")
        && event
            .get("sql_summary")
            .and_then(|summary| summary.get("preview"))
            .and_then(Value::as_str)
            .is_some_and(|sql| {
                !event
                    .get("sql_summary")
                    .and_then(|summary| summary.get("truncated"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    && sql.trim().eq_ignore_ascii_case("rollback")
            })
}

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

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("JSON output {} has no parent", path.display()))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("report"),
        std::process::id()
    ));
    let mut payload = serde_json::to_vec_pretty(value)?;
    payload.push(b'\n');
    fs::write(&temporary, payload)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests;
