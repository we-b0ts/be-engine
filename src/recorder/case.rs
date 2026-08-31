use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaseInvalidation {
    pub(crate) reason: String,
    pub(crate) message: String,
    pub(crate) context: Option<CaseInvalidationContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CaseInvalidationContext {
    pub(crate) category: String,
    pub(crate) elapsed_ms: u128,
    pub(crate) recorder_phase: String,
}

impl CaseInvalidation {
    pub(crate) fn new(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            message: message.into(),
            context: None,
        }
    }

    pub(crate) fn with_context(mut self, context: CaseInvalidationContext) -> Self {
        self.context = Some(context);
        self
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct PrimaryCaseDescriptor {
    pub(crate) version: u8,
    pub(crate) kind: PrimaryCaseKind,
    pub(crate) api_key: String,
    pub(crate) display_name: String,
    pub(crate) source_binding: PrimarySourceBinding,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrimaryCaseKind {
    Http,
    MotanRpc,
}

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
            kind: PrimaryCaseKind::Http,
            api_key: format!("http:{display_name}"),
            display_name,
            source_binding: PrimarySourceBinding::Http {
                method: method.to_ascii_uppercase(),
                path_pattern: path_pattern.to_string(),
            },
        }
    }

    pub(crate) fn http_path_pattern(&self) -> Option<&str> {
        match &self.source_binding {
            PrimarySourceBinding::Http { path_pattern, .. } => Some(path_pattern),
            PrimarySourceBinding::Motan { .. } => None,
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
            kind: PrimaryCaseKind::MotanRpc,
            api_key: format!("motan:{display_name}"),
            display_name,
            source_binding: PrimarySourceBinding::Motan {
                group: group.map(str::to_string),
                interface: interface.map(str::to_string),
                method: method.map(str::to_string),
                parameter_desc: parameter_desc.map(str::to_string),
                method_sign: method_sign.map(str::to_string),
            },
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
            descriptor.source_binding,
            PrimarySourceBinding::Motan { ref group, .. } if group.as_deref() == Some("abtest")
        ));
        assert_eq!(descriptor.kind, PrimaryCaseKind::MotanRpc);
    }
}
