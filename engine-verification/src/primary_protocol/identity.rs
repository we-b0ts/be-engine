//! Primary API identity retains each protocol's native routing dimensions.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApiIdentity {
    Http {
        method: String,
        route: String,
    },
    Motan {
        group: Option<String>,
        interface: Option<String>,
        method: Option<String>,
        parameter_desc: Option<String>,
        method_sign: Option<String>,
    },
}

impl ApiIdentity {
    pub fn protocol(&self) -> crate::protocol_contract::ProtocolKind {
        match self {
            Self::Http { .. } => crate::protocol_contract::ProtocolKind::Http,
            Self::Motan { .. } => crate::protocol_contract::ProtocolKind::Motan,
        }
    }
}
