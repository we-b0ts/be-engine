//! Runtime event classification is separate from process-rule schema validation.
use super::*;

pub(super) fn matches(rule: &BackgroundDependencyRuleConfig, event: &RecorderEvent) -> bool {
    if rule.trigger_source().is_some() {
        return false;
    }
    match (rule, event) {
        (
            BackgroundDependencyRuleConfig::Mysql { selector, .. },
            RecorderEvent::MysqlExchange(exchange),
        ) => selector.matches(exchange),
        (
            BackgroundDependencyRuleConfig::Http {
                authorities,
                methods,
                path_prefixes,
                ..
            },
            RecorderEvent::HttpExchange(exchange),
        ) => {
            let Some(authority) = exchange
                .authority
                .as_deref()
                .and_then(normalize_authority)
                .or_else(|| {
                    exchange
                        .uri
                        .parse::<Uri>()
                        .ok()
                        .and_then(|uri| uri.authority().map(ToString::to_string))
                        .as_deref()
                        .and_then(normalize_authority)
                })
            else {
                return false;
            };
            let path = exchange
                .uri
                .parse::<Uri>()
                .ok()
                .map(|uri| uri.path().to_string())
                .unwrap_or_else(|| {
                    exchange
                        .uri
                        .split('?')
                        .next()
                        .unwrap_or(&exchange.uri)
                        .to_string()
                });

            authorities
                .iter()
                .any(|candidate| normalize_authority(candidate).as_deref() == Some(&authority))
                && methods
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(&exchange.method))
                && path_prefixes.iter().any(|prefix| path.starts_with(prefix))
        }
        (BackgroundDependencyRuleConfig::Redis { .. }, RecorderEvent::RedisExchange(exchange)) => {
            let args = exchange
                .args
                .iter()
                .map(decode_capture)
                .collect::<Option<Vec<_>>>();
            !exchange.session_setup
                && exchange.replay_safe
                && args.as_deref().is_some_and(|args| {
                    redis_rule_matches(rule, exchange.target_port, &exchange.command, args)
                })
        }
        (
            BackgroundDependencyRuleConfig::Motan {
                group,
                interface_name,
                method_name,
                ..
            },
            RecorderEvent::MotanExchange(exchange),
        ) => {
            !exchange.heartbeat
                && exchange.group.as_deref() == Some(group)
                && exchange.interface_name.as_deref() == Some(interface_name)
                && exchange.method_name.as_deref() == Some(method_name)
        }
        _ => false,
    }
}
