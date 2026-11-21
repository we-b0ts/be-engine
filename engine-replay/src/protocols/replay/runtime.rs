//! Application entrypoints choose native providers before entering the shared runtime.
use crate::replay::RuntimeConfig;
use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf};

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
