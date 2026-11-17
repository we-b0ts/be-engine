//! Application assembly for independently registered dependency protocols.
use std::sync::{Arc, OnceLock};

use anyhow::Result;

pub use traffic_protocol::{
    DependencyProvider, EventHandler, FrameDecoder, Peer, Probe, ProviderRegistry, Recognition,
    Session,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DependencyProtocol(traffic_protocol::ProtocolId);

impl DependencyProtocol {
    pub const fn new(name: &'static str) -> Self {
        Self(traffic_protocol::ProtocolId::new(name))
    }
    pub const fn as_str(self) -> &'static str {
        self.0.as_str()
    }
    pub const fn id(self) -> traffic_protocol::ProtocolId {
        self.0
    }
}

impl From<DependencyProtocol> for traffic_protocol::ProtocolId {
    fn from(protocol: DependencyProtocol) -> Self {
        protocol.id()
    }
}

// Preserve the application assembly names used by existing callers.
#[allow(non_upper_case_globals)]
impl DependencyProtocol {
    pub const Http: Self = Self::new("http");
    pub const Mysql: Self = Self::new("mysql");
    pub const Redis: Self = Self::new("redis");
}

#[derive(Debug, Clone)]
pub struct DependencyProviders {
    providers: ProviderRegistry<DependencyProtocol>,
    bindings: traffic_policy_value::BindingRegistry,
}

impl Default for DependencyProviders {
    fn default() -> Self {
        Self {
            providers: ProviderRegistry::default(),
            bindings: traffic_policy_value::BindingRegistry::new(
                traffic_extensions::codecs().clone(),
            ),
        }
    }
}

impl std::ops::Deref for DependencyProviders {
    type Target = ProviderRegistry<DependencyProtocol>;
    fn deref(&self) -> &Self::Target {
        &self.providers
    }
}
impl std::ops::DerefMut for DependencyProviders {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.providers
    }
}
impl DependencyProviders {
    pub fn connection_provider(
        &self,
        protocol: traffic_protocol::ProtocolId,
    ) -> Result<&traffic_protocol::RegisteredProtocol<DependencyProtocol>> {
        self.registrations()
            .iter()
            .find(|entry| {
                entry.kind.id() == protocol || entry.provider.aliases().contains(&protocol.as_str())
            })
            .ok_or_else(|| anyhow::anyhow!("native connection provider is not registered"))
    }
    pub fn bindings(&self) -> &traffic_policy_value::BindingRegistry {
        &self.bindings
    }
    pub fn bindings_mut(&mut self) -> &mut traffic_policy_value::BindingRegistry {
        &mut self.bindings
    }
}

mod capture;
pub mod evidence;
#[cfg(test)]
pub(crate) mod mysql;
pub mod recording;
pub(crate) mod recording_preparation;
pub mod replay;

pub fn default_providers() -> Arc<DependencyProviders> {
    static PROVIDERS: OnceLock<Arc<DependencyProviders>> = OnceLock::new();
    Arc::clone(PROVIDERS.get_or_init(|| {
        let mut providers = DependencyProviders::default();
        traffic_extensions::install_protocols(&mut providers.providers, DependencyProtocol::new)
            .expect("extension catalog has unique protocol identities");
        providers
            .register_evidence("transport", Arc::new(evidence::TransportEvidence))
            .expect("unique transport evidence adapter");
        for protocol in replay::report::codecs::HISTORICAL_PROTOCOLS {
            providers
                .register_report_codec(
                    traffic_protocol::ProtocolId::new(protocol),
                    Arc::new(replay::report::codecs::Builtin),
                )
                .expect("unique built-in report codec");
        }
        Arc::new(providers)
    }))
}

pub(crate) fn http_session(
    providers: &DependencyProviders,
) -> Result<traffic_protocol_http::HttpSession> {
    providers.create_session(DependencyProtocol::Http)?.bind()
}

#[allow(dead_code)]
pub(crate) fn mysql_session(
    providers: &DependencyProviders,
) -> Result<traffic_protocol_mysql::MysqlSession> {
    providers.create_session(DependencyProtocol::Mysql)?.bind()
}

#[allow(dead_code)]
pub(crate) fn redis_session(
    providers: &DependencyProviders,
) -> Result<traffic_protocol_redis::RedisSession> {
    providers.create_session(DependencyProtocol::Redis)?.bind()
}

#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod value_rule_tests;
