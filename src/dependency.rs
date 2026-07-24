use std::net::Ipv4Addr;

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
    /// The exchange is expected to complete without response bytes.
    NoResponse,
}

impl DependencyExchangeOutcome {
    pub(crate) fn is_client_terminated(self) -> bool {
        self == Self::ClientTerminated
    }
}

/// A raw TCP endpoint advertised inside a recorded dependency response.
///
/// `advertised_ip` is the stable fake IP returned to the target process. Replay
/// must reserve that exact address before returning the recorded response.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DiscoveredTcpTarget {
    pub protocol: String,
    pub alias: String,
    pub advertised_ip: Ipv4Addr,
    pub upstream_ip: Ipv4Addr,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}
