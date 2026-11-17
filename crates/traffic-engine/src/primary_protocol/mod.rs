//! Typed primary inputs use static protocol dispatch and share execution authority.
//! Adapters execute recorded inputs; they never open expected response evidence.
pub mod assertion;
use anyhow::{Result, ensure};
use serde::Deserialize;

mod context;
mod http;
pub use http::close_timing::project as close_timing;
mod identity;
mod output;
#[cfg(test)]
mod tests;

use crate::protocol_contract::{
    NativeProtocolVersion, ProtocolContract, ProtocolKind, ProtocolRole,
};
pub(crate) use context::{CaseClock, CaseExecutionContext, ExecutionSettings};
pub(crate) use identity::ApiIdentity;
pub(crate) use output::{PrimaryMetadata, PrimaryObservation, PrimaryOutput};

pub(crate) enum PrimaryProtocol<'a> {
    Http(http::HttpPrimary<'a>),
}

pub(crate) trait NativePrimaryAdapter {
    fn api(&self) -> &ApiIdentity;
    fn native_version(&self) -> NativeProtocolVersion;
    async fn execute(&self, context: &CaseExecutionContext<'_>) -> Result<PrimaryOutput>;
}

impl NativePrimaryAdapter for PrimaryProtocol<'_> {
    fn api(&self) -> &ApiIdentity {
        match self {
            Self::Http(adapter) => adapter.api(),
        }
    }

    fn native_version(&self) -> NativeProtocolVersion {
        match self {
            Self::Http(adapter) => adapter.native_version(),
        }
    }

    async fn execute(&self, context: &CaseExecutionContext<'_>) -> Result<PrimaryOutput> {
        contract(self.api().protocol()).validate_version(self.native_version())?;
        ensure!(
            !context.remaining().is_zero(),
            "primary request budget expired before execution"
        );
        match self {
            Self::Http(adapter) => adapter.execute(context).await,
        }
    }
}

#[derive(Deserialize)]
struct Metadata {
    method: String,
    uri: String,
    #[serde(default)]
    api_pattern: Option<String>,
    #[serde(default)]
    timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    interaction: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    protocol_version: Option<String>,
    #[serde(default)]
    frame: Option<serde::de::IgnoredAny>,
}

impl<'a> PrimaryProtocol<'a> {
    pub(crate) fn from_recorded(bytes: &'a [u8]) -> Result<Self> {
        let metadata: Metadata = serde_json::from_slice(bytes)?;
        let version =
            crate::protocol_contract::primary_version(metadata.protocol_version.as_deref())?;
        match (version, metadata.frame.is_some()) {
            (NativeProtocolVersion::Http, false) => Ok(Self::Http(
                http::HttpPrimary::from_recorded(bytes, metadata)?,
            )),
            (NativeProtocolVersion::Motan1 | NativeProtocolVersion::Motan2, _) => {
                anyhow::bail!("Motan primary execution has no installed protocol implementation")
            }
            _ => anyhow::bail!(
                "primary native input requires a supported version and a complete matching frame"
            ),
        }
    }

    pub(crate) fn kind(&self) -> ProtocolKind {
        match self {
            Self::Http(_) => ProtocolKind::Http,
        }
    }

    pub(crate) fn has_interaction(&self) -> bool {
        matches!(self, Self::Http(adapter) if adapter.has_interaction())
    }
}

pub(crate) fn contract(protocol: ProtocolKind) -> ProtocolContract {
    use NativeProtocolVersion as V;
    let native_versions: &'static [V] = match protocol {
        ProtocolKind::Http => &[V::Http],
        _ => &[],
    };
    ProtocolContract {
        protocol,
        role: ProtocolRole::Primary,
        native_versions,
    }
}

pub(crate) mod recording;
