//! Native primary request identities and their stored Source bindings.
use crate::recorder::PrimaryCaseDescriptor;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub(crate) enum PrimarySourceBinding {
    Http {
        method: String,
        path_pattern: String,
    },
    Motan {
        group: Option<String>,
        interface: Option<String>,
        method: Option<String>,
        parameter_desc: Option<String>,
        method_sign: Option<String>,
    },
}

impl PrimaryCaseDescriptor {
    pub(crate) fn http(method: &str, path_pattern: &str) -> Self {
        let display_name = format!("{} {path_pattern}", method.to_ascii_uppercase());
        Self {
            version: 1,
            kind: "http".into(),
            api_key: format!("http:{display_name}"),
            display_name,
            source_binding: serde_json::to_value(PrimarySourceBinding::Http {
                method: method.to_ascii_uppercase(),
                path_pattern: path_pattern.to_string(),
            })
            .expect("native Source binding serializes"),
        }
    }

    pub(crate) fn http_path_pattern(&self) -> Option<&str> {
        if self.source_binding["protocol"] == "http" {
            self.source_binding["path_pattern"].as_str()
        } else {
            None
        }
    }

    pub(crate) fn motan(
        group: Option<&str>,
        interface: Option<&str>,
        method: Option<&str>,
        parameter_desc: Option<&str>,
        method_sign: Option<&str>,
    ) -> Self {
        let display_name = match (interface, method, parameter_desc, method_sign) {
            (Some(interface), Some(method), Some(parameter_desc), _) => {
                format!("{interface}#{method}({parameter_desc})")
            }
            (Some(interface), Some(method), None, _) => format!("{interface}#{method}"),
            (_, _, _, Some(method_sign)) => format!("method-sign:{method_sign}"),
            _ => "unknown".to_string(),
        };
        Self {
            version: 1,
            kind: "motan_rpc".into(),
            api_key: format!("motan:{display_name}"),
            display_name,
            source_binding: serde_json::to_value(PrimarySourceBinding::Motan {
                group: group.map(str::to_string),
                interface: interface.map(str::to_string),
                method: method.map(str::to_string),
                parameter_desc: parameter_desc.map(str::to_string),
                method_sign: method_sign.map(str::to_string),
            })
            .expect("native Source binding serializes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn motan_descriptor_excludes_group_from_api_identity_and_retains_it_in_binding() {
        let descriptor = PrimaryCaseDescriptor::motan(
            Some("abtest"),
            Some("com.weibo.AlchemyRpcService"),
            Some("getConfig"),
            Some("java.lang.String"),
            None,
        );

        assert_eq!(
            descriptor.api_key,
            "motan:com.weibo.AlchemyRpcService#getConfig(java.lang.String)"
        );
        assert_eq!(
            PrimaryCaseDescriptor::motan(
                Some("production"),
                Some("com.weibo.AlchemyRpcService"),
                Some("getConfig"),
                Some("java.lang.String"),
                None,
            )
            .api_key,
            descriptor.api_key
        );
        assert!(matches!(
            serde_json::from_value::<PrimarySourceBinding>(descriptor.source_binding).unwrap(),
            PrimarySourceBinding::Motan { ref group, .. } if group.as_deref() == Some("abtest")
        ));
        assert_eq!(descriptor.kind, "motan_rpc");
    }
}
