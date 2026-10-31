//! Protocol identity and native capabilities, independent of payload codecs and rules.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProtocolKind {
    Http,
    Redis,
    Mysql,
    Memcached,
    Motan,
    Kafka,
}

impl ProtocolKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Redis => "redis",
            Self::Mysql => "mysql",
            Self::Memcached => "memcached",
            Self::Motan => "motan",
            Self::Kafka => "kafka",
        }
    }
}

impl From<crate::policy::Protocol> for ProtocolKind {
    fn from(protocol: crate::policy::Protocol) -> Self {
        match protocol {
            crate::policy::Protocol::Http => Self::Http,
            crate::policy::Protocol::Redis => Self::Redis,
            crate::policy::Protocol::Mysql => Self::Mysql,
            crate::policy::Protocol::Memcached => Self::Memcached,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProtocolRole {
    Primary,
    Dependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeProtocolVersion {
    Http,
    MysqlClassic,
    RedisResp2,
    RedisResp3,
    MemcachedText,
    MemcachedBinary,
    Motan1,
    Motan2,
    Kafka,
}

/// Classify declared primary metadata once for execution and assertions.
/// The input driver additionally validates the complete native request frame.
pub(crate) fn primary_version(version: Option<&str>) -> Result<NativeProtocolVersion> {
    match version {
        None => Ok(NativeProtocolVersion::Http),
        Some("motan1") => Ok(NativeProtocolVersion::Motan1),
        Some("motan2") => Ok(NativeProtocolVersion::Motan2),
        Some(_) => anyhow::bail!("primary input declares an unsupported native protocol version"),
    }
}

impl NativeProtocolVersion {
    pub(crate) const fn protocol(self) -> ProtocolKind {
        match self {
            Self::Http => ProtocolKind::Http,
            Self::MysqlClassic => ProtocolKind::Mysql,
            Self::RedisResp2 | Self::RedisResp3 => ProtocolKind::Redis,
            Self::MemcachedText | Self::MemcachedBinary => ProtocolKind::Memcached,
            Self::Motan1 | Self::Motan2 => ProtocolKind::Motan,
            Self::Kafka => ProtocolKind::Kafka,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum CapabilitySupport {
    Supported,
    Unsupported { reason: &'static str },
}

impl CapabilitySupport {
    pub(crate) fn require(self) -> Result<()> {
        match self {
            Self::Supported => Ok(()),
            Self::Unsupported { reason } => anyhow::bail!("{reason}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct ProtocolContract {
    pub(crate) protocol: ProtocolKind,
    pub(crate) role: ProtocolRole,
    pub(crate) native_versions: &'static [NativeProtocolVersion],
}

impl ProtocolContract {
    pub(crate) fn validate_version(self, version: NativeProtocolVersion) -> Result<()> {
        ensure!(
            version.protocol() == self.protocol && self.native_versions.contains(&version),
            "{} {:?} adapter does not support native version {version:?}",
            self.protocol.as_str(),
            self.role,
        );
        Ok(())
    }
}
