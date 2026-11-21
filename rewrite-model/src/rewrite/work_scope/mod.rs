use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RewriteWorkScope {
    Api { api: String },
}

impl RewriteWorkScope {
    pub fn binding_key(&self) -> String {
        match self {
            Self::Api { api } => api.clone(),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Api { api } => format!("API {api}"),
        }
    }
}
