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

// Preserve the application assembly names used by existing callers.
#[allow(non_upper_case_globals)]
impl DependencyProtocol {
    pub const Http: Self = Self::new("http");
    pub const Mysql: Self = Self::new("mysql");
    pub const Redis: Self = Self::new("redis");
}

#[derive(Debug, Clone, Default)]
pub struct DependencyProviders {
    providers: ProviderRegistry<DependencyProtocol>,
    bindings: traffic_replay::rules::BindingRegistry,
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
    pub fn bindings(&self) -> &traffic_replay::rules::BindingRegistry {
        &self.bindings
    }
    pub fn bindings_mut(&mut self) -> &mut traffic_replay::rules::BindingRegistry {
        &mut self.bindings
    }
}

mod capture;
pub(crate) mod evidence;
pub(crate) mod mysql;

pub(crate) type RecordingDriver = fn(
    tokio::net::TcpStream,
    tokio::net::TcpStream,
    crate::AppState,
    traffic_protocol::connection::ConnectionInfo,
) -> traffic_protocol::connection::NativeFuture<'static, ()>;

/// Application bindings supply policy-aware hosts for independently compiled drivers.
pub(crate) fn recording_driver(protocol: DependencyProtocol) -> Option<RecordingDriver> {
    match protocol {
        DependencyProtocol::Mysql => Some(mysql::record_connected),
        _ => None,
    }
}

pub fn default_providers() -> Arc<DependencyProviders> {
    static PROVIDERS: OnceLock<Arc<DependencyProviders>> = OnceLock::new();
    Arc::clone(PROVIDERS.get_or_init(|| {
        let mut providers = DependencyProviders::default();
        for (kind, provider) in [
            (
                DependencyProtocol::Http,
                Arc::new(traffic_protocol_http::HttpProvider) as Arc<dyn DependencyProvider>,
            ),
            (
                DependencyProtocol::Mysql,
                Arc::new(traffic_protocol_mysql::MysqlProvider) as Arc<dyn DependencyProvider>,
            ),
            (
                DependencyProtocol::Redis,
                Arc::new(traffic_protocol_redis::RedisProvider) as Arc<dyn DependencyProvider>,
            ),
        ] {
            providers
                .register(kind, provider)
                .expect("unique built-in dependency provider");
        }
        providers
            .register_evidence("existing", Arc::new(evidence::ExistingEvidence))
            .expect("unique existing evidence adapter");
        providers
            .register_evidence("transport", Arc::new(evidence::TransportEvidence))
            .expect("unique transport evidence adapter");
        Arc::new(providers)
    }))
}

pub(crate) fn http_session(
    providers: &DependencyProviders,
) -> Result<traffic_protocol_http::HttpSession> {
    providers.create_session(DependencyProtocol::Http)?.bind()
}

pub(crate) fn mysql_session(
    providers: &DependencyProviders,
) -> Result<traffic_protocol_mysql::MysqlSession> {
    providers.create_session(DependencyProtocol::Mysql)?.bind()
}

pub(crate) fn redis_session(
    providers: &DependencyProviders,
) -> Result<traffic_protocol_redis::RedisSession> {
    providers.create_session(DependencyProtocol::Redis)?.bind()
}

#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod value_rule_tests;
