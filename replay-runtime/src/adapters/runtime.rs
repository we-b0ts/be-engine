use super::*;
#[cfg(any(test, feature = "test-support"))]
pub use crate::ReplayAllowedUnusedHttpConfig;
use crate::protocols::DependencyProviders;
use crate::replay::{self, ReplayEgressCounterReader, ReplayLifecycleConfig, ReplayTimerConfig};
pub use crate::{MysqlReplayConfig, ReplayConfig};
use anyhow::Result;
use loading::SourceLoader;
#[cfg(any(test, feature = "test-support"))]
use std::net::SocketAddr;
use std::sync::Arc;
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
    run_replay_with_timer_config(config, lifecycle, counter_reader, None).await
}

pub async fn run_replay_with_timer_config(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
    counter_reader: Option<ReplayEgressCounterReader>,
    timers: Option<ReplayTimerConfig>,
) -> Result<()> {
    let loader = SourceLoader::new(&config);
    replay::run::<ReplayProtocols>(
        config.into(),
        lifecycle,
        counter_reader,
        crate::protocols::default_providers(),
        loader,
        timers,
        false,
    )
    .await
}

pub async fn run_session_replay(
    config: ReplayConfig,
    lifecycle: ReplayLifecycleConfig,
    counter_reader: Option<ReplayEgressCounterReader>,
    timers: Option<ReplayTimerConfig>,
) -> Result<()> {
    let loader = SourceLoader::new(&config);
    replay::run::<ReplayProtocols>(
        config.into(),
        lifecycle,
        counter_reader,
        crate::protocols::default_providers(),
        loader,
        timers,
        true,
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
    replay::run::<ReplayProtocols>(
        config.into(),
        lifecycle,
        counter_reader,
        providers,
        loader,
        None,
        false,
    )
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
            (dns_listen, tcp_listen),
            lifecycle,
            providers,
            loader,
            Default::default(),
            false,
        )
        .await
    }
}
