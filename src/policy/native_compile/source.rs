//! Static scope checks for acquisition, proven origins and finite sharing.
use anyhow::{Result, ensure};

use super::*;

pub(super) fn validate(rule: &NativeRule) -> Result<()> {
    match &rule.effect {
        NativeEffect::CaptureHttp(effect) => {
            empty_match(rule)?;
            revision(&effect.source_revision)?;
            ensure!(
                (1..=4096).contains(&effect.case_paths.len()),
                "capture scope requires 1..4096 paths"
            );
            for path in &effect.case_paths {
                crate::path_pattern::validate_path_pattern(path)?;
            }
        }
        NativeEffect::CaptureBreeze(effect) => {
            empty_match(rule)?;
            ensure!(
                !effect.snapshot_dir.as_os_str().is_empty(),
                "Breeze capture requires a snapshot directory"
            );
            ensure!(
                (1..=4096).contains(&effect.resources.len()),
                "Breeze capture requires bounded resources"
            );
            for resource in &effect.resources {
                text(resource, "Breeze resource", 1024)?;
            }
        }
        NativeEffect::CaptureHttpResponse(effect) => {
            empty_match(rule)?;
            ensure!(
                (1..=64).contains(&effect.authorities.len())
                    && (1..=32).contains(&effect.methods.len()),
                "capture response requires bounded authorities and methods"
            );
            for authority in &effect.authorities {
                authority.parse::<hyper::http::uri::Authority>()?;
            }
            for method in &effect.methods {
                ensure!(
                    method.parse::<hyper::Method>().is_ok()
                        && method == &method.to_ascii_uppercase(),
                    "capture response requires uppercase methods"
                );
            }
            match &effect.path {
                CapturePath::Exact { value } => crate::path_pattern::validate_literal_path(value)?,
                CapturePath::Pattern { value } => {
                    crate::path_pattern::validate_path_pattern(value)?
                }
            }
            ensure!(
                effect.status_codes.iter().all(|s| (100..=599).contains(s)),
                "invalid capture response status"
            );
            for content_type in &effect.content_types {
                text(content_type, "capture content type", 128)?;
            }
            match &effect.contract {
                CaptureResponseContract::Urls { pointers } => {
                    ensure!(
                        (1..=128).contains(&pointers.len()),
                        "URL capture requires 1..128 pointers"
                    );
                    for pointer in pointers {
                        proven(pointer, |pointer| {
                            compiler::validate_pointer(pointer, false)
                        })?;
                    }
                }
                CaptureResponseContract::Kubeconfig {
                    kubectl_binary,
                    proxy_listen,
                } => {
                    text(kubectl_binary, "kubectl binary", 1024)?;
                    ensure!(
                        proxy_listen.ip().is_loopback() && proxy_listen.port() > 0,
                        "kubeconfig proxy must use loopback and nonzero port"
                    );
                }
                CaptureResponseContract::VintageNaming { services, clusters } => {
                    ensure!(
                        services.len() <= 4096 && clusters.len() <= 4096,
                        "naming capture exceeds bounds"
                    );
                }
                CaptureResponseContract::VintageCacheConfig => (),
            }
        }
        NativeEffect::ProcessOwned(effect) => {
            empty_match(rule)?;
            if !effect.source_revision.is_empty() {
                revision(&effect.source_revision)?;
            }
            if let Some(origin) = &effect.origin {
                proven(origin, validate_origin)?;
            }
            match &effect.selector {
                ProcessSelector::Mysql {
                    selector,
                    transaction_members,
                    ..
                } => {
                    mysql(selector)?;
                    ensure!(
                        transaction_members.len() <= 64,
                        "too many origin transaction members"
                    );
                    for member in transaction_members {
                        proven(member, mysql)?;
                    }
                }
                ProcessSelector::Http {
                    authorities,
                    methods,
                    path_prefixes,
                } => {
                    ensure!(
                        (1..=64).contains(&authorities.len())
                            && (1..=32).contains(&methods.len())
                            && (1..=64).contains(&path_prefixes.len()),
                        "process HTTP requires bounded authorities, methods and paths"
                    );
                    for authority in authorities {
                        authority.parse::<hyper::http::uri::Authority>()?;
                    }
                    for method in methods {
                        method.parse::<hyper::Method>()?;
                    }
                    for prefix in path_prefixes {
                        ensure!(
                            prefix.starts_with('/') && prefix.len() <= 1024,
                            "invalid process HTTP prefix"
                        );
                    }
                    ensure!(
                        effect.origin.is_none(),
                        "HTTP process traffic has no API origin adapter"
                    );
                }
                ProcessSelector::Memcached {
                    operation,
                    key_start,
                    key_end,
                    initial_load_timeout_ms,
                    ..
                } => {
                    ensure!(
                        operation == "get"
                            && key_start <= key_end
                            && key_end - key_start <= 4096
                            && *initial_load_timeout_ms > 0,
                        "invalid Memcached process series"
                    );
                    ensure!(
                        effect.origin.is_none(),
                        "Memcached process traffic has no API origin adapter"
                    );
                }
                ProcessSelector::Redis {
                    ports,
                    keys,
                    key_templates,
                    key_sequence,
                    script,
                    ..
                } => {
                    ensure!(
                        (1..=64).contains(&ports.len()) && ports.iter().all(|p| *p > 0),
                        "process Redis requires bounded ports"
                    );
                    ensure!(
                        keys.len() <= 128 && key_templates.len() <= 64 && key_sequence.len() <= 64,
                        "process Redis keys exceed bounds"
                    );
                    for key in keys {
                        validate_key(key)?;
                    }
                    if let Some(script) = script {
                        proven(script, |script| {
                            ensure!(
                                effect.origin.is_some()
                                    && script.sha1.len() == 40
                                    && script
                                        .sha1
                                        .bytes()
                                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                                "origin script requires an API origin and lowercase SHA-1"
                            );
                            ensure!(
                                (1..=32).contains(&script.keys.len())
                                    && (1..=64).contains(&script.argv_count)
                                    && script.identity_argv_index < script.argv_count,
                                "origin script KEYS/ARGV exceeds bounds"
                            );
                            for key in &script.keys {
                                validate_key(key)?;
                            }
                            Ok(())
                        })?;
                    }
                }
                ProcessSelector::Motan {
                    group,
                    interface,
                    method,
                } => {
                    text(group, "Motan group", 256)?;
                    text(interface, "Motan interface", 256)?;
                    text(method, "Motan method", 128)?;
                    ensure!(
                        effect.origin.is_none(),
                        "Motan process traffic has no API origin adapter"
                    );
                }
            }
        }
        NativeEffect::FiniteSharing(effect) => {
            ensure!(
                rule.selector.api.is_none() && rule.when.is_none(),
                "finite sharing is recording-owned, without case conditions"
            );
            match effect {
                FiniteSharingEffect::Http => {
                    resource(&rule.selector, Protocol::Http)?;
                    ensure!(
                        rule.selector.operation.is_some() && rule.selector.path.is_some(),
                        "HTTP sharing requires exact method and path"
                    );
                }
                FiniteSharingEffect::Redis {
                    hash_field,
                    response_time,
                } => {
                    resource(&rule.selector, Protocol::Redis)?;
                    ensure!(
                        rule.selector
                            .key
                            .as_ref()
                            .and_then(NativeKeySelector::exact)
                            .is_some(),
                        "Redis sharing requires an exact key"
                    );
                    ensure!(
                        matches!(rule.selector.operation.as_deref(), Some("GET" | "HGET")),
                        "Redis sharing supports GET/HGET"
                    );
                    ensure!(
                        (rule.selector.operation.as_deref() == Some("HGET"))
                            == hash_field.is_some(),
                        "HGET sharing requires one hash field"
                    );
                    ensure!(
                        (1..=32).contains(&response_time.len()),
                        "Redis sharing requires explicit response-time fields"
                    );
                    for (pointer, time) in response_time {
                        compiler::validate_pointer(pointer, false)?;
                        proven(time, validate_time)?;
                        ensure!(
                            time.contract.anchor
                                == super::super::TimeAnchor::DependencyRequestStart,
                            "shared Redis response rebasing uses dependency request clocks"
                        );
                    }
                }
            }
        }
        _ => unreachable!("source validator receives source and sharing effects"),
    }
    Ok(())
}

fn mysql(selector: &MysqlProcessSelector) -> Result<()> {
    ensure!(
        selector.resource.protocol == Protocol::Mysql
            && selector
                .resource
                .database
                .as_ref()
                .and_then(super::super::Database::name)
                .is_some()
            && selector.resource.username.is_some(),
        "process MySQL requires exact database and username"
    );
    selector.resource.endpoint.validate()?;
    text(&selector.sql, "process SQL", 8192)?;
    crate::config::mysql_tables::TableMatcher::new(
        &selector.tables,
        &selector.table_patterns,
        selector.table_series.as_ref(),
    )?;
    Ok(())
}

fn validate_origin(origin: &ApiOrigin) -> Result<()> {
    let (_, path) = api_parts(&origin.api)?;
    ensure!(
        !path.contains('*'),
        "API origin requires an exact inbound path"
    );
    ensure!(
        origin.request_body.len() <= 16 && origin.capture.len() == 1,
        "API origin requires at most 16 predicates and exactly one capture"
    );
    for pointer in origin.request_body.keys() {
        compiler::validate_pointer(pointer, false)?;
    }
    for (name, capture) in &origin.capture {
        identifier(name, "origin binding")?;
        proven(capture, |capture| {
            ensure!(
                capture.resource.protocol == Protocol::Mysql
                    && capture
                        .resource
                        .database
                        .as_ref()
                        .and_then(super::super::Database::name)
                        .is_some()
                    && capture.resource.username.is_some(),
                "origin capture requires exact MySQL resource identity"
            );
            capture.resource.endpoint.validate()?;
            ensure!(
                (1..=16).contains(&capture.row_match.len())
                    && capture
                        .row_match
                        .values()
                        .all(|v| matches!(v, Literal::Integer(_) | Literal::String(_))),
                "origin row_match requires 1..16 string/integer predicates"
            );
            for column in capture.row_match.keys() {
                identifier(column, "origin row column")?;
            }
            identifier(&capture.column, "captured column")?;
            crate::config::mysql_tables::TableMatcher::new(
                &capture.tables,
                &capture.table_patterns,
                None,
            )?;
            Ok(())
        })?;
    }
    Ok(())
}

fn revision(value: &str) -> Result<()> {
    ensure!(
        value
            .strip_prefix("sha256:")
            .is_some_and(|hash| hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
        "Source revision must be a lowercase SHA-256 fingerprint"
    );
    Ok(())
}
