use super::*;
use crate::protocols::DependencyProviders;
use crate::replay::{self, ReplayEgressCounterReader, ReplayLifecycleConfig};
use anyhow::Result;
use loading::SourceLoader;
use std::{net::SocketAddr, sync::Arc};
pub use traffic_engine::{MysqlReplayConfig, ReplayAllowedUnusedHttpConfig, ReplayConfig};
pub async fn run_replay(config: ReplayConfig) -> Result<()> {
    run_replay_with_lifecycle(config, ReplayLifecycleConfig::default()).await
}

pub async fn run_replay_with_lifecycle(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
) -> Result<()> {
    run_replay_with_counters(config, lifecycle, None).await
}

pub async fn run_replay_with_counters(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
    counter_reader: Option<ReplayEgressCounterReader>,
) -> Result<()> {
    run_replay_with_providers(
        config,
        lifecycle,
        counter_reader,
        crate::protocols::default_providers(),
    )
    .await
}

pub async fn run_replay_with_providers(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
    counter_reader: Option<ReplayEgressCounterReader>,
    providers: Arc<DependencyProviders>,
) -> Result<()> {
    let loader = SourceLoader::new(&config);
    replay::run::<ReplayProtocols>(config.into(), lifecycle, counter_reader, providers, loader)
        .await
}

pub async fn run_mysql_replay(config: MysqlReplayConfig) -> Result<()> {
    run_replay(config).await
}

#[cfg(any(test, feature = "test-support"))]
impl replay::Runtime<ReplayProtocols> {
    pub(crate) async fn load(
        config: ReplayConfig,
        dns_listen: SocketAddr,
        tcp_listen: SocketAddr,
    ) -> Result<Self> {
        Self::load_with_lifecycle(
            config,
            dns_listen,
            tcp_listen,
            ReplayLifecycleConfig::default(),
        )
        .await
    }
    pub(crate) async fn load_with_lifecycle(
        config: ReplayConfig,
        dns_listen: SocketAddr,
        tcp_listen: SocketAddr,
        lifecycle: ReplayLifecycleConfig,
    ) -> Result<Self> {
        Self::load_with_providers(
            config,
            dns_listen,
            tcp_listen,
            lifecycle,
            crate::protocols::default_providers(),
        )
        .await
    }
    pub(crate) async fn load_with_providers(
        config: ReplayConfig,
        dns_listen: SocketAddr,
        tcp_listen: SocketAddr,
        lifecycle: ReplayLifecycleConfig,
        providers: Arc<DependencyProviders>,
    ) -> Result<Self> {
        let loader = SourceLoader::new(&config);
        Self::from_source(
            config.into(),
            dns_listen,
            tcp_listen,
            lifecycle,
            providers,
            loader,
        )
        .await
    }
}
