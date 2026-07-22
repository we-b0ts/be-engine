use serde::{Deserialize, Serialize};

pub(crate) mod termination;

/// How a dependency exchange ended from the application's point of view.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DependencyExchangeOutcome {
    /// The dependency produced a response that was delivered to the client.
    #[default]
    Response,
    /// The client ended the connection while it was still waiting for a response.
    ClientTerminated,
    /// The protocol command intentionally has no response.
    NoResponse,
}

impl DependencyExchangeOutcome {
    pub(crate) fn is_client_terminated(self) -> bool {
        self == Self::ClientTerminated
    }
}
