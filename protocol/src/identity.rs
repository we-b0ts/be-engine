//! Process-local identities assigned by protocol implementations at registration.
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProtocolId(&'static str);

impl ProtocolId {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
