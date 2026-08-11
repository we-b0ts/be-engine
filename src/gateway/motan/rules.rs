use motan_codec::RequestEnvelope;

use crate::config::MotanGatewayRuleConfig;
use crate::recorder::PrimaryCaseDescriptor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Match {
    pub(super) rule_name: String,
    pub(super) descriptor: PrimaryCaseDescriptor,
    pub(super) directory: String,
}

pub(super) fn evaluate_request(
    rules: &[MotanGatewayRuleConfig],
    envelope: &RequestEnvelope,
) -> Option<Match> {
    let api = envelope.api()?;
    let rule_name = if rules.is_empty() {
        "default".to_string()
    } else {
        let rule = rules
            .iter()
            .find(|rule| rule_matches(rule, envelope.group.as_deref(), &api))?;
        rule.name.clone().unwrap_or_else(|| "unnamed".to_string())
    };
    let descriptor = PrimaryCaseDescriptor::motan(
        envelope.group.as_deref(),
        envelope.interface_name.as_deref(),
        envelope.method_name.as_deref(),
        envelope.parameter_desc.as_deref(),
        envelope.method_sign.as_deref(),
    );
    let directory = api_directory(&descriptor.api_key);
    Some(Match {
        rule_name,
        descriptor,
        directory,
    })
}

fn rule_matches(rule: &MotanGatewayRuleConfig, group: Option<&str>, api: &str) -> bool {
    matches_optional(&rule.groups, group)
        && (rule.apis.is_empty() || rule.apis.iter().any(|allowed| allowed == api))
}

fn matches_optional(allowed: &[String], actual: Option<&str>) -> bool {
    allowed.is_empty() || actual.is_some_and(|actual| allowed.iter().any(|item| item == actual))
}

fn api_directory(api_key: &str) -> String {
    const MAX_PREFIX_BYTES: usize = 160;
    let sanitized = crate::recorder::sanitize_path_component(api_key);
    let mut prefix = sanitized
        .char_indices()
        .take_while(|(index, _)| *index < MAX_PREFIX_BYTES)
        .map(|(_, character)| character)
        .collect::<String>();
    if prefix.is_empty() {
        prefix.push_str("motan-api");
    }
    format!("{prefix}-{:016x}", fnv1a64(api_key.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> RequestEnvelope {
        RequestEnvelope {
            group: Some("abtest".to_string()),
            interface_name: Some("com.weibo.AlchemyRpcService".to_string()),
            method_name: Some("getConfig".to_string()),
            parameter_desc: Some("java.lang.String".to_string()),
            ..RequestEnvelope::default()
        }
    }

    #[test]
    fn empty_rules_match_every_identified_business_request() {
        let matched = evaluate_request(&[], &envelope()).unwrap();

        assert_eq!(matched.rule_name, "default");
        assert_eq!(
            matched.descriptor.api_key,
            "motan:abtest/com.weibo.AlchemyRpcService#getConfig(java.lang.String)"
        );
        assert!(matched.directory.starts_with("motan-abtest-com.weibo"));
    }

    #[test]
    fn rules_match_canonical_api_and_optional_group() {
        let rules = [MotanGatewayRuleConfig {
            name: Some("alchemy".to_string()),
            groups: vec!["abtest".to_string()],
            apis: vec!["com.weibo.AlchemyRpcService#getConfig(java.lang.String)".to_string()],
        }];

        assert_eq!(
            evaluate_request(&rules, &envelope()).unwrap().rule_name,
            "alchemy"
        );
        let mut other_overload = envelope();
        other_overload.parameter_desc = Some("java.lang.Integer".to_string());
        assert!(evaluate_request(&rules, &other_overload).is_none());

        let mut other_group = envelope();
        other_group.group = Some("production".to_string());
        assert!(evaluate_request(&rules, &other_group).is_none());
    }

    #[test]
    fn rules_accept_method_sign_identity() {
        let envelope = RequestEnvelope {
            method_sign: Some("stable-sign".to_string()),
            ..RequestEnvelope::default()
        };
        let rules = [MotanGatewayRuleConfig {
            apis: vec!["method-sign:stable-sign".to_string()],
            ..Default::default()
        }];

        assert!(evaluate_request(&rules, &envelope).is_some());
    }
}
