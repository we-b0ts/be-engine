//! Explicit relationship scopes keep clock names independent of sampled entities.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "ScopeDocument", into = "ScopeDocument")]
pub enum ValueScope {
    #[default]
    Shared,
    ArrayElement,
    Entity {
        relative_pointer: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum ScopeDocument {
    Named(ScopeName),
    Entity { relative_pointer: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScopeName {
    Shared,
    ArrayElement,
}

impl From<ScopeDocument> for ValueScope {
    fn from(value: ScopeDocument) -> Self {
        match value {
            ScopeDocument::Named(ScopeName::Shared) => Self::Shared,
            ScopeDocument::Named(ScopeName::ArrayElement) => Self::ArrayElement,
            ScopeDocument::Entity { relative_pointer } => Self::Entity { relative_pointer },
        }
    }
}

impl From<ValueScope> for ScopeDocument {
    fn from(value: ValueScope) -> Self {
        match value {
            ValueScope::Shared => Self::Named(ScopeName::Shared),
            ValueScope::ArrayElement => Self::Named(ScopeName::ArrayElement),
            ValueScope::Entity { relative_pointer } => Self::Entity { relative_pointer },
        }
    }
}

impl ValueScope {
    pub fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }

    pub fn validate(&self, pointer: &str) -> Result<()> {
        match self {
            Self::Shared => Ok(()),
            Self::ArrayElement => {
                ensure!(
                    pointer.split('/').any(|part| part == "*"),
                    "array_element clock_scope requires an array wildcard field"
                );
                Ok(())
            }
            Self::Entity { relative_pointer } => {
                ensure!(
                    relative_pointer.starts_with("../") && !relative_pointer.contains('*'),
                    "entity clock_scope requires an exact sibling pointer"
                );
                traffic_value::path::validate(&relative_pointer[2..], false)?;
                ensure!(
                    relative_pointer[3..]
                        .split('/')
                        .all(|part| !matches!(part, "." | "..")),
                    "clock_scope cannot escape its sibling scope"
                );
                ensure!(
                    !pointer.is_empty() && self.peer_pointer(pointer).as_deref() != Some(pointer),
                    "clock_scope requires a distinct identity sibling"
                );
                Ok(())
            }
        }
    }

    pub fn peer_pointer(&self, pointer: &str) -> Option<String> {
        let Self::Entity {
            relative_pointer, ..
        } = self
        else {
            return None;
        };
        let (parent, _) = pointer.rsplit_once('/')?;
        Some(format!("{parent}{}", relative_pointer.strip_prefix("..")?))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopeKey {
    #[default]
    Shared,
    ArrayElement(String),
    Entity([u8; 32]),
}
impl ScopeKey {
    pub fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }
}
