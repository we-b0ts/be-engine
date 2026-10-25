//! Runtime event classification is separate from process-rule schema validation.
use super::*;

impl BackgroundDependencyRuleConfig {
    pub(crate) fn matches_http_request(
        &self,
        method: &str,
        uri: &Uri,
        authority: Option<&str>,
    ) -> bool {
        let Self::Http {
            authorities,
            methods,
            path_prefixes,
            ..
        } = self
        else {
            return false;
        };
        let Some(authority) = uri
            .authority()
            .map(|value| value.as_str())
            .or(authority)
            .and_then(normalize_authority)
        else {
            return false;
        };
        authorities
            .iter()
            .any(|candidate| authority_matches(candidate, &authority))
            && methods
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(method))
            && path_prefixes
                .iter()
                .any(|prefix| uri.path().starts_with(prefix))
    }
}

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
                .any(|candidate| authority_matches(candidate, &authority))
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

/// A declared host selects that host at its recorded port. An explicit port
/// remains an exact port selector; no default HTTP/HTTPS port is inferred.
pub(super) fn authority_matches(candidate: &str, actual: &str) -> bool {
    let (Ok(candidate), Ok(actual)) = (candidate.parse::<Authority>(), actual.parse::<Authority>())
    else {
        return false;
    };
    candidate.host().eq_ignore_ascii_case(actual.host())
        && match candidate.port_u16() {
            Some(port) => actual.port_u16() == Some(port),
            None => candidate.as_str().eq_ignore_ascii_case(candidate.host()),
        }
}
