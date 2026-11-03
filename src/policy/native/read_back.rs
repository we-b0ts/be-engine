//! Closed key-only GET-from-SET permission; content identities stay global.
use super::{
    IdentityCapture, IdentityType, NativeEffect, NativeKeySelector, NativeMatch, NativeRule,
    RedisReadBack,
};

pub fn is_key_only_read_back(rule: &NativeRule) -> bool {
    let NativeEffect::Identity(effect) = &rule.effect else {
        return false;
    };
    let Some(key) = &rule.selector.key else {
        return false;
    };
    let bounded = match key {
        NativeKeySelector::Exact { value } => {
            !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
        }
        NativeKeySelector::Affix { prefix, suffix }
        | NativeKeySelector::Numeric { prefix, suffix } => {
            (!prefix.is_empty() || !suffix.is_empty())
                && prefix.len().saturating_add(suffix.len()) <= 1024
                && !prefix.chars().chain(suffix.chars()).any(char::is_control)
        }
    };
    bounded
        && rule.when.is_none()
        && rule.selector
            == (NativeMatch {
                operation: Some("SET".into()),
                key: Some(key.clone()),
                ..Default::default()
            })
        && effect.value_type == IdentityType::String
        && effect.format.is_none()
        && effect.references.is_empty()
        && effect.capture
            == (IdentityCapture::RedisArgument {
                index: 1,
                when: None,
                json_pointer: None,
                copies: vec![],
                derived_from: None,
            })
        && effect.read_back.len() == 1
        && effect.read_back[0].contract
            == (RedisReadBack {
                operation: "GET".into(),
                write_operation: "SET".into(),
                argument_index: 1,
                json_pointers: vec![],
                // Observation counts are an independent permission. Both
                // finite value rendering and explicit native epochs retain
                // this same bounded raw SET-to-GET value contract.
                state_epochs: effect.read_back[0].contract.state_epochs,
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::native::{IdentityEffect, Proven};

    fn rule() -> NativeRule {
        NativeRule {
            id: "read-state".into(),
            selector: NativeMatch {
                operation: Some("SET".into()),
                key: Some(NativeKeySelector::Exact {
                    value: "current".into(),
                }),
                ..Default::default()
            },
            effect: NativeEffect::Identity(IdentityEffect {
                value_type: IdentityType::String,
                format: None,
                capture: IdentityCapture::RedisArgument {
                    index: 1,
                    when: None,
                    json_pointer: None,
                    copies: vec![],
                    derived_from: None,
                },
                references: vec![],
                read_back: vec![Proven {
                    contract: RedisReadBack {
                        operation: "GET".into(),
                        write_operation: "SET".into(),
                        argument_index: 1,
                        json_pointers: vec![],
                        state_epochs: true,
                    },
                    proof: None,
                }],
            }),
            proof: None,
            when: None,
        }
    }

    #[test]
    fn key_only_readback_has_no_hidden_api_resource_or_capture_permission() {
        assert!(is_key_only_read_back(&rule()));
        let mut finite = rule();
        if let NativeEffect::Identity(effect) = &mut finite.effect {
            effect.read_back[0].contract.state_epochs = false;
        }
        assert!(is_key_only_read_back(&finite));
        for change in [
            "api",
            "path",
            "operation",
            "index",
            "json",
            "read_operation",
            "unbounded",
        ] {
            let mut rule = rule();
            match change {
                "api" => rule.selector.api = Some("POST /tasks".into()),
                "path" => rule.selector.path = Some("/other".into()),
                "operation" => rule.selector.operation = Some("RPUSH".into()),
                "unbounded" => {
                    rule.selector.key = Some(NativeKeySelector::Affix {
                        prefix: String::new(),
                        suffix: String::new(),
                    })
                }
                _ => {
                    if let NativeEffect::Identity(effect) = &mut rule.effect {
                        match change {
                            "index" => {
                                effect.capture = IdentityCapture::RedisArgument {
                                    index: 2,
                                    when: None,
                                    json_pointer: None,
                                    copies: vec![],
                                    derived_from: None,
                                }
                            }
                            "json" => effect.read_back[0]
                                .contract
                                .json_pointers
                                .push("/id".into()),
                            _ => effect.read_back[0].contract.operation = "LRANGE".into(),
                        }
                    }
                }
            }
            assert!(!is_key_only_read_back(&rule), "accepted {change}");
        }
    }
}
