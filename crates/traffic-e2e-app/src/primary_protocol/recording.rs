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
}
