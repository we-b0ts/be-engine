//! Named endpoint aliases. Content formats belong to the root JSON/MySQL policy.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceDeclaration {
    pub resource: super::Resource,
}
