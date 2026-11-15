//! Application entrypoints choose native providers before entering the shared runtime.
use super::{ReplayProtocols, loading::SourceLoader};
use crate::protocols::DependencyProviders;
use crate::replay::{self, ReplayEgressCounterReader, ReplayLifecycleConfig, RuntimeConfig};
use anyhow::Result;
use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf, sync::Arc};

#[derive(Debug, Clone)]
pub struct ReplayConfig {
    pub case_dir: PathBuf,
    pub selected_case_ids: Vec<String>,
    pub dns_listen: SocketAddr,
    pub tcp_listen: SocketAddr,
    pub fake_cidr: String,
    pub report_path: Option<PathBuf>,
    pub session_path: Option<PathBuf>,
    pub control_socket_path: Option<PathBuf>,
    pub ca_cert_path: Option<PathBuf>,
    pub ca_key_path: Option<PathBuf>,
    pub policy_path: Option<PathBuf>,
    pub http_ignore_query_params: Vec<String>,
    pub process_owned_dependencies: Vec<crate::BackgroundDependencyRuleConfig>,
    pub allowed_unused_http: Option<ReplayAllowedUnusedHttpConfig>,
}

#[derive(Debug, Clone)]
pub struct ReplayAllowedUnusedHttpConfig {
    pub config_path: PathBuf,
    pub hosts: BTreeSet<String>,
}

pub type MysqlReplayConfig = ReplayConfig;

impl From<ReplayConfig> for RuntimeConfig {
    fn from(config: ReplayConfig) -> Self {
        Self {
            case_dir: config.case_dir,
            selected_case_ids: config.selected_case_ids,
            dns_listen: config.dns_listen,
            tcp_listen: config.tcp_listen,
            fake_cidr: config.fake_cidr,
            report_path: config.report_path,
            session_path: config.session_path,
            control_socket_path: config.control_socket_path,
            ca_cert_path: config.ca_cert_path,
            ca_key_path: config.ca_key_path,
            policy_path: config.policy_path,
            process_owned_dependencies: config.process_owned_dependencies,
        }
    }
}

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

#[cfg(test)]
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
