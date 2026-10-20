use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

pub(crate) mod http_limits;
pub(crate) mod termination;
#[cfg(test)]
mod tests;

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
    /// A complete observation of a transport ending, possibly after response bytes.
    Terminated(DependencyTermination),
}

impl DependencyExchangeOutcome {
    pub(crate) fn is_client_terminated(self) -> bool {
        self == Self::ClientTerminated
            || matches!(self, Self::Terminated(end) if end.side == TerminationSide::Client)
    }

    pub(crate) fn is_server_terminated(self) -> bool {
        matches!(self, Self::Terminated(end) if end.side == TerminationSide::Server)
    }

    pub(crate) fn termination(self) -> Option<DependencyTermination> {
        match self {
            Self::Terminated(end) => Some(end),
            _ => None,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Response => "response",
            Self::ClientTerminated => "client_terminated",
            Self::NoResponse => "no_response",
            Self::Terminated(end) => match end.side {
                TerminationSide::Client => "client_terminated",
                TerminationSide::Server => "server_terminated",
                TerminationSide::Engine => "engine_terminated",
            },
        }
    }

    pub(crate) fn validate(self) -> anyhow::Result<()> {
        if let Self::Terminated(end) = self {
            anyhow::ensure!(
                end.side != TerminationSide::Engine,
                "engine cleanup is not a peer termination contract"
            );
            anyhow::ensure!(
                matches!(
                    (end.kind, end.scope),
                    (TerminationKind::Eof, TerminationScope::WriteHalf)
                        | (TerminationKind::Reset, TerminationScope::Connection)
                        | (TerminationKind::Cancelled, TerminationScope::Stream)
                ),
                "termination mechanism does not match its transport scope"
            );
        }
        Ok(())
    }
}

/// Transport facts are independent of business success and capture integrity.
/// Their time is `duration_ms`, measured at observation rather than cleanup.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DependencyTermination {
    pub side: TerminationSide,
    pub kind: TerminationKind,
    pub scope: TerminationScope,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TerminationSide {
    Client,
    Server,
    Engine,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TerminationKind {
    Eof,
    Reset,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TerminationScope {
    WriteHalf,
    Connection,
    Stream,
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
