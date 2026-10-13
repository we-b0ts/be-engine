use anyhow::{Result, ensure};

use super::canonical_authority;
use crate::config::{BackgroundDependencyRuleConfig, RedisKeyPatternConfig};

pub(super) fn ensure_same(
    existing: &BackgroundDependencyRuleConfig,
    requested: &BackgroundDependencyRuleConfig,
) -> Result<()> {
    ensure!(
        compatible(existing, requested, false),
        "process-owned dependency rule name {:?} already exists with a different selector; choose a new name instead of broadening it",
        existing.name()
    );
    Ok(())
}

pub(super) fn covers(
    existing: &BackgroundDependencyRuleConfig,
    requested: &BackgroundDependencyRuleConfig,
) -> bool {
    if existing.trigger_source().is_some() || requested.trigger_source().is_some() {
        return api_trigger_same(existing, requested);
    }
    match (existing, requested) {
        (
            BackgroundDependencyRuleConfig::Mysql { selector: left, .. },
            BackgroundDependencyRuleConfig::Mysql {
                selector: right, ..
            },
        ) => left == right,
        (
            BackgroundDependencyRuleConfig::Http {
                authorities: existing_authorities,
                methods: existing_methods,
                path_prefixes: existing_paths,
                ..
            },
            BackgroundDependencyRuleConfig::Http {
                authorities: requested_authorities,
                methods: requested_methods,
                path_prefixes: requested_paths,
                ..
            },
        ) => {
            requested_authorities.iter().all(|requested| {
                existing_authorities.iter().any(|existing| {
                    canonical_authority(existing).ok() == canonical_authority(requested).ok()
                })
            }) && requested_methods.iter().all(|requested| {
                existing_methods
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(requested))
            }) && requested_paths.iter().all(|requested| {
                existing_paths
                    .iter()
                    .any(|existing| requested.starts_with(existing))
            })
        }
        (
            BackgroundDependencyRuleConfig::Redis { command, .. },
            BackgroundDependencyRuleConfig::Redis { .. },
        ) if supports_key_selectors(command) => redis_key_selector_rule_covers(existing, requested),
        _ => compatible(existing, requested, true),
    }
}

pub(super) fn merge_compatible_redis_key_selector_rule(
    rules: &mut [BackgroundDependencyRuleConfig],
    requested: &BackgroundDependencyRuleConfig,
) -> Result<Option<String>> {
    let BackgroundDependencyRuleConfig::Redis {
        name: requested_name,
        ports: requested_ports,
        command: requested_command,
        keys: requested_keys,
        key_patterns: requested_patterns,
        fields: requested_fields,
        source_evidence: requested_evidence,
        ..
    } = requested
    else {
        return Ok(None);
    };
    if requested.trigger_source().is_some() || !supports_key_selectors(requested_command) {
        return Ok(None);
    }

    let candidates = rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            redis_key_selector_wire_shape_matches(
                rule,
                requested_ports,
                requested_command,
                requested_fields,
            )
            .then_some(index)
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(None);
    }
    let named = rules.iter().position(|rule| rule.name() == requested_name);
    if named.is_some_and(|index| !candidates.contains(&index)) {
        anyhow::bail!(
            "process-owned dependency rule name {requested_name:?} already exists with a different selector; choose a new name instead of broadening it"
        );
    }
    let selected = named.or_else(|| (candidates.len() == 1).then_some(candidates[0]));
    let Some(selected) = selected else {
        anyhow::bail!(
            "Redis {requested_command} background selector matches multiple existing rules with the same ports and fields; use one existing rule name to select the merge target"
        );
    };

    let BackgroundDependencyRuleConfig::Redis {
        name,
        keys,
        key_patterns,
        source_evidence,
        ..
    } = &mut rules[selected]
    else {
        unreachable!("Redis merge candidate changed variant")
    };
    merge_strings(keys, requested_keys);
    merge_patterns(key_patterns, requested_patterns);
    merge_evidence(source_evidence, requested_evidence);
    Ok(Some(name.clone()))
}

fn redis_key_selector_wire_shape_matches(
    existing: &BackgroundDependencyRuleConfig,
    requested_ports: &[u16],
    requested_command: &str,
    requested_fields: &[String],
) -> bool {
    let BackgroundDependencyRuleConfig::Redis {
        ports,
        command,
        fields,
        ..
    } = existing
    else {
        return false;
    };
    supports_key_selectors(command)
        && same_set(ports, requested_ports)
        && command.eq_ignore_ascii_case(requested_command)
        && fields == requested_fields
}

fn redis_key_selector_rule_covers(
    existing: &BackgroundDependencyRuleConfig,
    requested: &BackgroundDependencyRuleConfig,
) -> bool {
    let (
        BackgroundDependencyRuleConfig::Redis {
            ports: existing_ports,
            command: existing_command,
            keys: existing_keys,
            key_patterns: existing_patterns,
            fields: existing_fields,
            ..
        },
        BackgroundDependencyRuleConfig::Redis {
            ports: requested_ports,
            command: requested_command,
            keys: requested_keys,
            key_patterns: requested_patterns,
            fields: requested_fields,
            ..
        },
    ) = (existing, requested)
    else {
        return false;
    };
    same_set(existing_ports, requested_ports)
        && existing_command.eq_ignore_ascii_case(requested_command)
        && existing_fields == requested_fields
        && requested_keys.iter().all(|key| {
            existing_keys.contains(key)
                || existing_patterns
                    .iter()
                    .any(|pattern| pattern_matches(pattern, key))
        })
        && requested_patterns
            .iter()
            .all(|pattern| existing_patterns.contains(pattern))
}

fn compatible(
    existing: &BackgroundDependencyRuleConfig,
    requested: &BackgroundDependencyRuleConfig,
    require_exact_sets: bool,
) -> bool {
    if existing.trigger_source().is_some() || requested.trigger_source().is_some() {
        return api_trigger_same(existing, requested);
    }
    match (existing, requested) {
        (
            BackgroundDependencyRuleConfig::Mysql { selector: left, .. },
            BackgroundDependencyRuleConfig::Mysql {
                selector: right, ..
            },
        ) => left == right,
        (
            BackgroundDependencyRuleConfig::Http {
                authorities: existing_authorities,
                methods: existing_methods,
                path_prefixes: existing_paths,
                ..
            },
            BackgroundDependencyRuleConfig::Http {
                authorities: requested_authorities,
                methods: requested_methods,
                path_prefixes: requested_paths,
                ..
            },
        ) => {
            (!require_exact_sets || existing_authorities.len() == requested_authorities.len())
                && existing_authorities.iter().all(|authority| {
                    requested_authorities.iter().any(|requested| {
                        canonical_authority(authority).ok() == canonical_authority(requested).ok()
                    })
                })
                && (!require_exact_sets || existing_methods.len() == requested_methods.len())
                && existing_methods.iter().all(|method| {
                    requested_methods
                        .iter()
                        .any(|requested| method.eq_ignore_ascii_case(requested))
                })
                && existing_paths == requested_paths
        }
        (
            BackgroundDependencyRuleConfig::Memcached {
                breeze_identity: existing_identity,
                command: existing_command,
                key_start: existing_start,
                key_end: existing_end,
                key_separator: existing_separator,
                key_suffix: existing_suffix,
                ..
            },
            BackgroundDependencyRuleConfig::Memcached {
                breeze_identity: requested_identity,
                command: requested_command,
                key_start: requested_start,
                key_end: requested_end,
                key_separator: requested_separator,
                key_suffix: requested_suffix,
                ..
            },
        ) => {
            existing_identity == requested_identity
                && existing_command == requested_command
                && existing_start == requested_start
                && existing_end == requested_end
                && existing_separator == requested_separator
                && existing_suffix == requested_suffix
        }
        (
            BackgroundDependencyRuleConfig::Redis {
                ports: existing_ports,
                command: existing_command,
                keys: existing_keys,
                key_patterns: existing_patterns,
                key_prefix: existing_prefix,
                key_suffix: existing_suffix,
                fields: existing_fields,
                ..
            },
            BackgroundDependencyRuleConfig::Redis {
                ports: requested_ports,
                command: requested_command,
                keys: requested_keys,
                key_patterns: requested_patterns,
                key_prefix: requested_prefix,
                key_suffix: requested_suffix,
                fields: requested_fields,
                ..
            },
        ) => {
            (!require_exact_sets || existing_ports.len() == requested_ports.len())
                && existing_ports
                    .iter()
                    .all(|port| requested_ports.contains(port))
                && existing_command == requested_command
                && existing_keys == requested_keys
                && existing_patterns == requested_patterns
                && existing_prefix == requested_prefix
                && existing_suffix == requested_suffix
                && existing_fields == requested_fields
        }
        (
            BackgroundDependencyRuleConfig::Motan {
                group: existing_group,
                interface_name: existing_interface,
                method_name: existing_method,
                ..
            },
            BackgroundDependencyRuleConfig::Motan {
                group: requested_group,
                interface_name: requested_interface,
                method_name: requested_method,
                ..
            },
        ) => {
            existing_group == requested_group
                && existing_interface == requested_interface
                && existing_method == requested_method
        }
        _ => false,
    }
}

fn merge_strings(existing: &mut Vec<String>, requested: &[String]) {
    existing.extend(requested.iter().cloned());
    existing.sort();
    existing.dedup();
}

fn merge_patterns(existing: &mut Vec<RedisKeyPatternConfig>, requested: &[RedisKeyPatternConfig]) {
    existing.extend(requested.iter().cloned());
    existing.sort_by(|left, right| {
        (&left.prefix, &left.suffix, left.numeric_middle).cmp(&(
            &right.prefix,
            &right.suffix,
            right.numeric_middle,
        ))
    });
    existing.dedup();
}

fn merge_evidence(existing: &mut String, requested: &str) {
    if existing != requested {
        existing.push_str("; ");
        existing.push_str(requested);
    }
}

fn same_set<T: Ord + Copy>(left: &[T], right: &[T]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort();
    right.sort();
    left == right
}

fn pattern_matches(pattern: &RedisKeyPatternConfig, key: &str) -> bool {
    let Some(middle) = key
        .strip_prefix(&pattern.prefix)
        .and_then(|value| value.strip_suffix(&pattern.suffix))
    else {
        return false;
    };
    pattern.numeric_middle && !middle.is_empty() && middle.bytes().all(|byte| byte.is_ascii_digit())
}

fn supports_key_selectors(command: &str) -> bool {
    matches!(
        command.to_ascii_uppercase().as_str(),
        "HGET" | "HMGET" | "HSCAN"
    )
}

fn api_trigger_same(
    a: &BackgroundDependencyRuleConfig,
    b: &BackgroundDependencyRuleConfig,
) -> bool {
    match (a, b) {
        (
            BackgroundDependencyRuleConfig::Mysql {
                trigger_source: Some(at),
                identity_value_index: ai,
                include_transaction_boundaries: ati,
                transaction_members: atm,
                selector: a,
                ..
            },
            BackgroundDependencyRuleConfig::Mysql {
                trigger_source: Some(bt),
                identity_value_index: bi,
                include_transaction_boundaries: bti,
                transaction_members: btm,
                selector: b,
                ..
            },
        ) => at == bt && ai == bi && a == b && ati == bti && atm == btm,

        (
            BackgroundDependencyRuleConfig::Redis {
                trigger_source: Some(at),
                ports: ap,
                command: ac,
                key_templates: ak,
                arguments: aa,
                key_sequence: aks,
                script: asc,
                ..
            },
            BackgroundDependencyRuleConfig::Redis {
                trigger_source: Some(bt),
                ports: bp,
                command: bc,
                key_templates: bk,
                arguments: ba,
                key_sequence: bks,
                script: bsc,
                ..
            },
        ) => at == bt && ap == bp && ac == bc && ak == bk && aa == ba && aks == bks && asc == bsc,
        _ => false,
    }
}

/// A same-name ordinary SELECT rule may be narrowed to the exact same shape
/// with a verified API origin. The reverse operation is never an implicit merge.
pub(super) fn narrows_mysql_origin(
    existing: &BackgroundDependencyRuleConfig,
    requested: &BackgroundDependencyRuleConfig,
) -> bool {
    matches!((existing, requested),
        (BackgroundDependencyRuleConfig::Mysql {trigger_source: None, selector: a, ..},
         BackgroundDependencyRuleConfig::Mysql {trigger_source: Some(_), selector: b, ..}) if a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redis_rule(
        name: &str,
        ports: &[u16],
        command: &str,
        keys: &[&str],
        patterns: &[&str],
        fields: &[&str],
    ) -> BackgroundDependencyRuleConfig {
        BackgroundDependencyRuleConfig::Redis {
            key_sequence: Vec::new(),
            script: None,
            trigger_source: None,
            key_templates: Vec::new(),
            arguments: Vec::new(),
            name: name.to_string(),
            ports: ports.to_vec(),
            command: command.to_string(),
            keys: keys.iter().map(|key| (*key).to_string()).collect(),
            key_patterns: patterns
                .iter()
                .map(|prefix| RedisKeyPatternConfig {
                    prefix: (*prefix).to_string(),
                    suffix: String::new(),
                    numeric_middle: true,
                })
                .collect(),
            key_prefix: String::new(),
            key_suffix: String::new(),
            initial_load_timeout_ms: None,
            fields: fields.iter().map(|field| (*field).to_string()).collect(),
            source_revision: String::new(),
            source_evidence: format!("evidence for {name}"),
        }
    }

    #[test]
    fn merges_hash_keys_and_patterns_for_the_same_wire_shape() {
        let mut rules = vec![redis_rule(
            "bootstrap",
            &[50600],
            "HGET",
            &["exp:business:all"],
            &["exp:assign:collection:"],
            &["version"],
        )];
        let mut requested = redis_rule(
            "scheduled",
            &[50600],
            "HGET",
            &["traffic-result"],
            &["exp:config:collection:"],
            &["version"],
        );
        let BackgroundDependencyRuleConfig::Redis {
            source_evidence, ..
        } = &mut requested
        else {
            unreachable!()
        };
        *source_evidence = "scheduled refresh".to_string();

        let effective_name =
            merge_compatible_redis_key_selector_rule(&mut rules, &requested).unwrap();

        assert_eq!(effective_name.as_deref(), Some("bootstrap"));
        let BackgroundDependencyRuleConfig::Redis {
            keys,
            key_patterns,
            source_evidence,
            ..
        } = &rules[0]
        else {
            unreachable!()
        };
        assert_eq!(
            keys.iter().map(String::as_str).collect::<Vec<_>>(),
            ["exp:business:all", "traffic-result"]
        );
        assert_eq!(
            key_patterns
                .iter()
                .map(|pattern| pattern.prefix.as_str())
                .collect::<Vec<_>>(),
            ["exp:assign:collection:", "exp:config:collection:"]
        );
        assert_eq!(source_evidence, "evidence for bootstrap; scheduled refresh");
    }

    #[test]
    fn does_not_merge_hash_rules_with_different_ports_commands_or_fields() {
        let base = redis_rule(
            "bootstrap",
            &[50600],
            "HGET",
            &["exp:business:all"],
            &[],
            &["version"],
        );
        for requested in [
            redis_rule(
                "different-port",
                &[50601],
                "HGET",
                &["traffic-result"],
                &[],
                &["version"],
            ),
            redis_rule(
                "different-command",
                &[50600],
                "HMGET",
                &["traffic-result"],
                &[],
                &["version"],
            ),
            redis_rule(
                "different-fields",
                &[50600],
                "HGET",
                &["traffic-result"],
                &[],
                &["value"],
            ),
        ] {
            let mut rules = vec![base.clone()];
            assert_eq!(
                merge_compatible_redis_key_selector_rule(&mut rules, &requested).unwrap(),
                None
            );
            assert_eq!(rules.as_slice(), std::slice::from_ref(&base));
        }
    }

    #[test]
    fn rejects_an_ambiguous_merge_target() {
        let mut rules = vec![
            redis_rule(
                "bootstrap-a",
                &[50600],
                "HGET",
                &["exp:business:all"],
                &[],
                &["version"],
            ),
            redis_rule(
                "bootstrap-b",
                &[50600],
                "HGET",
                &["traffic-result"],
                &[],
                &["version"],
            ),
        ];
        let requested = redis_rule(
            "scheduled",
            &[50600],
            "HGET",
            &["another-key"],
            &[],
            &["version"],
        );

        let error = merge_compatible_redis_key_selector_rule(&mut rules, &requested).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("matches multiple existing rules")
        );
    }

    #[test]
    fn rejects_a_conflicting_requested_name_before_merging_another_rule() {
        let mut rules = vec![
            redis_rule(
                "scheduled",
                &[50601],
                "HGET",
                &["different-port-key"],
                &[],
                &["version"],
            ),
            redis_rule(
                "bootstrap",
                &[50600],
                "HGET",
                &["exp:business:all"],
                &[],
                &["version"],
            ),
        ];
        let requested = redis_rule(
            "scheduled",
            &[50600],
            "HGET",
            &["traffic-result"],
            &[],
            &["version"],
        );

        let error = merge_compatible_redis_key_selector_rule(&mut rules, &requested).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("already exists with a different selector")
        );
    }
}
