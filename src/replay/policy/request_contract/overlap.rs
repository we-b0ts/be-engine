//! Reject ambiguous request-contract ownership before Replay begins.
use super::super::{dynamic_values::DynamicValueCapture, redis_value::RedisSelector};
use super::*;

pub(in crate::replay::policy) fn validate(
    document: &super::super::config::ReplayPolicyDocument,
) -> Result<()> {
    for (index, rule) in document
        .dependency_rules
        .iter()
        .enumerate()
        .filter(|(_, r)| is_request_rule(r))
    {
        for (_, other) in document
            .dependency_rules
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
        {
            if rule.protocol != other.protocol
                || rule
                    .target
                    .host
                    .as_ref()
                    .zip(other.target.host.as_ref())
                    .is_none_or(|(a, b)| !a.eq_ignore_ascii_case(b))
                || rule.target.port != other.target.port
            {
                continue;
            }
            if let (Some(a), Some(b)) = (&rule.case_selector, &other.case_selector)
                && (a.method != b.method
                    || !crate::path_pattern::path_patterns_overlap(&a.path, &b.path))
            {
                continue;
            }
            let overlap = match (&rule.redis, &other.redis) {
                (Some(RedisSelector::Requests(a)), Some(RedisSelector::Requests(b))) => {
                    a.database == b.database
                        && a.key.overlaps(&b.key)
                        && a.commands
                            .iter()
                            .any(|c| b.commands.iter().any(|d| c.command == d.command))
                }
                (Some(RedisSelector::Requests(a)), Some(RedisSelector::Value(b))) => {
                    a.key.overlaps(&b.key)
                }
                (Some(RedisSelector::Requests(a)), Some(RedisSelector::Lock(b))) => {
                    a.key.overlaps(&b.lock.key)
                }
                _ => rule
                    .http
                    .as_ref()
                    .zip(other.http.as_ref())
                    .is_some_and(|(a, b)| {
                        b.multipart.is_some()
                            && a.method == b.method
                            && crate::path_pattern::path_patterns_overlap(&a.path, &b.path)
                    }),
            };
            ensure!(
                !overlap,
                "dependency request rule overlaps another request normalization"
            );
        }
        for dynamic in &document.dynamic_values {
            if rule.case_selector.as_ref().is_some_and(|case| {
                !crate::path_pattern::path_patterns_overlap(&case.path, &dynamic.api)
            }) {
                continue;
            }
            let overlap = match (&rule.redis, &rule.http, &dynamic.capture) {
                (
                    Some(RedisSelector::Requests(a)),
                    _,
                    DynamicValueCapture::Redis {
                        target,
                        database,
                        command,
                        key,
                        argument_index,
                        json_pointer,
                    },
                ) => {
                    rule.target
                        .host
                        .as_ref()
                        .is_some_and(|h| h.eq_ignore_ascii_case(&target.host))
                        && rule.target.port == Some(target.port)
                        && a.database == *database
                        && a.key.overlaps(key)
                        && a.commands
                            .iter()
                            .filter(|c| c.command == *command)
                            .any(|c| {
                                c.argument_values.get(argument_index).is_some_and(|field| {
                                    match (field, json_pointer) {
                                        (config::ArgumentRule::Json(json), Some(pointer)) => {
                                            json.json.keys().any(|other| {
                                                super::super::response_locations_overlap(
                                                    pointer, other,
                                                )
                                            })
                                        }
                                        _ => true,
                                    }
                                })
                            })
                }
                (
                    _,
                    Some(a),
                    DynamicValueCapture::Http {
                        target,
                        method,
                        path,
                        ..
                    },
                ) => {
                    rule.target
                        .host
                        .as_ref()
                        .is_some_and(|h| h.eq_ignore_ascii_case(&target.host))
                        && rule.target.port == Some(target.port)
                        && a.method == *method
                        && crate::path_pattern::path_patterns_overlap(&a.path, path)
                }
                _ => false,
            };
            ensure!(
                !overlap,
                "dependency request contract overlaps a dynamic capture"
            );
        }
    }
    Ok(())
}
