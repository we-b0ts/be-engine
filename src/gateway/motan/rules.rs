use motan_codec::RequestEnvelope;

use crate::config::MotanGatewayRuleConfig;
use crate::recorder::{PrimaryCaseDescriptor, PrimarySourceBinding};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Match {
    pub(crate) rule_name: String,
    pub(crate) descriptor: PrimaryCaseDescriptor,
    pub(crate) directory: String,
}

pub(crate) fn evaluate_request(
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
    let directory = api_directory(&descriptor);
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

pub(crate) fn api_directory(descriptor: &PrimaryCaseDescriptor) -> String {
    const MAX_PREFIX_BYTES: usize = 96;
    let sanitized = crate::recorder::sanitize_path_component(&short_api_name(descriptor));
    let mut prefix = sanitized
        .char_indices()
        .take_while(|(index, _)| *index < MAX_PREFIX_BYTES)
        .map(|(_, character)| character)
        .collect::<String>();
    if prefix.is_empty() {
        prefix.push_str("motan-api");
    }
    format!("{prefix}-{:016x}", fnv1a64(descriptor.api_key.as_bytes()))
}

fn short_api_name(descriptor: &PrimaryCaseDescriptor) -> String {
    let PrimarySourceBinding::Motan {
        interface,
        method,
        parameter_desc,
        method_sign,
        ..
    } = &descriptor.source_binding
    else {
        return "motan-api".to_string();
    };
    match (interface.as_deref(), method.as_deref()) {
        (Some(interface), Some(method)) => {
            let mut parts = vec![
                short_qualified_name(interface).to_string(),
                method.to_string(),
            ];
            if let Some(parameter_desc) = parameter_desc {
                parts.extend(parameter_desc.split(',').map(short_parameter_type));
            }
            parts.join("-")
        }
        _ => method_sign
            .as_deref()
            .map(|method_sign| format!("method-sign-{method_sign}"))
            .unwrap_or_else(|| "motan-api".to_string()),
    }
}

fn short_parameter_type(parameter: &str) -> String {
    let mut parameter = parameter.trim();
    let mut array_dimensions = 0;
    while let Some(element) = parameter.strip_suffix("[]") {
        parameter = element.trim_end();
        array_dimensions += 1;
    }
    let short = short_qualified_name(parameter);
    if array_dimensions == 0 {
        short.to_string()
    } else {
        format!("{short}{}", "Array".repeat(array_dimensions))
    }
}

fn short_qualified_name(value: &str) -> &str {
    value.rsplit(['.', '$']).next().unwrap_or(value)
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
            "motan:com.weibo.AlchemyRpcService#getConfig(java.lang.String)"
        );
        assert_eq!(
            matched.directory,
            "AlchemyRpcService-getConfig-String-7fffc7627051a903"
        );
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
    fn different_groups_share_the_same_api_directory() {
        let first = evaluate_request(&[], &envelope()).unwrap();
        let mut other_group = envelope();
        other_group.group = Some("production".to_string());
        let second = evaluate_request(&[], &other_group).unwrap();

        assert_eq!(first.descriptor.api_key, second.descriptor.api_key);
        assert_eq!(first.directory, second.directory);
        assert_ne!(
            first.descriptor.source_binding,
            second.descriptor.source_binding
        );
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

    #[test]
    fn directory_exposes_short_interface_method_and_parameter_names() {
        let descriptor = PrimaryCaseDescriptor::motan(
            Some("hwyun-weibo-abtest-rpc-core-motan2"),
            Some("com.weibo.abtest.traffic.rpc.AlchemyRpcService"),
            Some("getConfig"),
            Some("com.weibo.abtest.traffic.rpc.model.ConfigRequest"),
            None,
        );

        assert_eq!(
            api_directory(&descriptor),
            "AlchemyRpcService-getConfig-ConfigRequest-444028e2c132700d"
        );
    }

    #[test]
    fn directory_shortens_multiple_primitive_and_array_parameters() {
        let primitives = PrimaryCaseDescriptor::motan(
            Some("hwyun-weibo-abtest-rpc-core-motan2"),
            Some("com.weibo.abtest.traffic.rpc.AlchemyRpcService"),
            Some("getList"),
            Some("long,long"),
            None,
        );
        let array = PrimaryCaseDescriptor::motan(
            Some("hwyun-weibo-abtest-rpc-core-motan2"),
            Some("com.weibo.abtest.traffic.rpc.AlchemyRpcService"),
            Some("getExperimentTrafficRule"),
            Some("byte[]"),
            None,
        );

        assert_eq!(
            api_directory(&primitives),
            "AlchemyRpcService-getList-long-long-70e0606b37b3fedf"
        );
        assert_eq!(
            api_directory(&array),
            "AlchemyRpcService-getExperimentTrafficRule-byteArray-843a9bd3356df6bb"
        );
    }
}
