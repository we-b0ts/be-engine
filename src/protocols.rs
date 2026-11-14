//! Application assembly for independently registered dependency protocols.
use std::sync::{Arc, OnceLock};

use anyhow::Result;

pub use traffic_protocol::{
    DependencyProvider, EventHandler, FrameDecoder, Peer, Probe, ProviderRegistry, Recognition,
    Session,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyProtocol {
    Http,
    Mysql,
    Redis,
}

pub type DependencyProviders = ProviderRegistry<DependencyProtocol>;

mod capture;
pub(crate) mod evidence;

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
