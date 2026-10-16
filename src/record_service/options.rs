//! Online deployment settings over optional project Recorder configuration.

use crate::config::SourceTrafficPolicyConfig;
use crate::{
    AppConfig, ArtifactOwner, ArtifactsConfig, HttpGatewayFallbackMode,
    HttpGatewayFixedResponseConfig,
};
use anyhow::{Context, Result, ensure};
use clap::{Args, ValueEnum};
use std::{ffi::OsString, net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CoordinationBackend {
    Redis,
}

#[derive(Args)]
pub struct RecordOptions {
    /// Reuse Recorder settings and the single project.policy reference.
    #[arg(
        long = "config",
        env = "TRAFFIC_E2E_PROJECT_CONFIG",
        value_name = "PATH"
    )]
    pub config_path: Option<PathBuf>,
    #[arg(
        long,
        env = "TRAFFIC_E2E_RECORD_LISTEN",
        default_value = "0.0.0.0:4080"
    )]
    pub listen: SocketAddr,
    /// Optional gateway discovery and request reservation backend.
    #[arg(long, env = "TRAFFIC_E2E_RECORDING_COORDINATION", value_enum)]
    pub coordination: Option<CoordinationBackend>,
    /// Optional 14-digit UTC run identifier; generated atomically when omitted.
    #[arg(long, value_parser = parse_run_id)]
    pub run_id: Option<String>,
    /// Reachable HTTP origin published to gateways, including the exposed port.
    #[arg(long, env = "TRAFFIC_E2E_RECORD_URL", requires = "coordination")]
    pub advertise_url: Option<String>,
    /// Coordination Redis URL; independent of Source business Redis.
    #[arg(
        long,
        env = "TRAFFIC_E2E_RECORDING_REDIS_URL",
        hide_env_values = true,
        requires = "coordination"
    )]
    pub redis_url: Option<String>,
    #[arg(
        long,
        env = "TRAFFIC_E2E_RECORDING_PREFIX",
        default_value = "recording"
    )]
    pub prefix: String,
    #[arg(long, env = "TRAFFIC_E2E_RECORDING_URL_KEY")]
    pub url_key: Option<String>,
    #[arg(long, env = "TRAFFIC_E2E_RECORDING_SCOPE", default_value = "all-apis")]
    pub scope: String,
    #[arg(
        long,
        env = "TRAFFIC_E2E_RECORDER_LISTEN",
        default_value = "127.0.0.1:4081"
    )]
    pub recorder_listen: SocketAddr,
    #[arg(
        long,
        env = "TRAFFIC_E2E_SOURCE_ORIGIN",
        default_value = "http://127.0.0.1:8080"
    )]
    pub source_origin: String,
    #[arg(long, env = "TRAFFIC_E2E_SOURCE_READY_PATH")]
    pub ready_path: Option<String>,
    #[arg(
        long,
        env = "TRAFFIC_E2E_DATA_ROOT",
        default_value = "/data/traffic-e2e"
    )]
    pub data_root: PathBuf,
    /// Assign private storage and finalized recording runs to this numeric UID:GID.
    #[arg(long, env = "TRAFFIC_E2E_ARTIFACT_OWNER", value_name = "UID:GID")]
    pub artifact_owner: Option<ArtifactOwner>,
    #[arg(long, env = "TRAFFIC_E2E_SOURCE_WORKDIR", default_value = "/app")]
    pub source_workdir: PathBuf,
    /// Unified traffic-policy/v1; with --config it must name project.policy.
    #[arg(long, env = "TRAFFIC_E2E_POLICY", value_name = "PATH")]
    pub policy: Option<PathBuf>,
    #[arg(long, env = "TRAFFIC_E2E_DNS_UPSTREAM")]
    pub dns_upstream: Option<SocketAddr>,
    #[arg(long, default_value = "300", value_parser = clap::value_parser!(u64).range(1..))]
    pub startup_timeout_seconds: u64,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub request_timeout_seconds: Option<u64>,
    /// Override the project case limit; without project configuration it is unlimited.
    #[arg(long, env = "TRAFFIC_E2E_CASE_LIMIT")]
    pub case_limit: Option<std::num::NonZeroUsize>,
    /// Development only: disable fixed-identity DNS/fake-IP interception.
    #[arg(long)]
    pub no_interception: bool,
    #[arg(last = true, required = true, num_args = 1..)]
    pub source_command: Vec<OsString>,
}

impl RecordOptions {
    pub(super) fn storage_owner(&self) -> Result<ArtifactOwner> {
        let owner = match self.artifact_owner {
            Some(owner) => owner,
            None => ArtifactOwner::invoking()?,
        };
        ensure!(
            owner.uid() != crate::TRAFFIC_PROCESS_UID,
            "recording artifact owner cannot use the reserved Source UID"
        );
        ensure!(
            self.artifact_owner.is_none() || crate::local_interception::effective_uid() == 0,
            "--artifact-owner requires a root controller"
        );
        Ok(owner)
    }

    pub fn initialize_storage(&mut self) -> Result<String> {
        let owner = self.storage_owner()?;
        std::fs::create_dir_all(&self.data_root)?;
        self.data_root = self.data_root.canonicalize()?;
        super::source::prepare_recordings_root(&self.data_root, owner)?;
        let key = crate::platform::encryption_key::load_or_create(&self.data_root)?;
        owner.assign_path_to(&self.data_root.join(crate::repository::LOCAL_SECRETS_ROOT))?;
        owner.assign_path_to(
            &self
                .data_root
                .join(crate::repository::LOCAL_ENCRYPTION_KEY_PATH),
        )?;
        Ok(key)
    }

    pub(super) fn discovery_key(&self) -> String {
        self.url_key
            .clone()
            .unwrap_or_else(|| format!("{}:url", self.prefix))
    }

    pub(super) fn config(&self) -> Result<AppConfig> {
        ensure!(
            !self.source_command.is_empty(),
            "Source command is required"
        );
        if self.coordination.is_some() {
            ensure!(
                self.advertise_url.is_some(),
                "Redis coordination requires --advertise-url"
            );
            ensure!(
                self.redis_url.is_some(),
                "Redis coordination requires --redis-url"
            );
        }
        if let Some(run_id) = &self.run_id {
            parse_run_id(run_id).map_err(anyhow::Error::msg)?;
        }
        brz_http_gateway::AdmissionTicket::new(&self.scope, "validation")?;
        ensure!(
            self.discovery_key() != format!("{}:max-gateways", self.prefix)
                && !self
                    .discovery_key()
                    .starts_with(&format!("{}:gateway:", self.prefix))
                && !self
                    .discovery_key()
                    .starts_with(&format!("{}:inflight:", self.prefix)),
            "discovery key conflicts with coordination keys"
        );
        ensure!(
            self.recorder_listen.ip().is_loopback(),
            "recorder listener must be loopback-only"
        );
        ensure!(
            self.listen.port() != self.recorder_listen.port(),
            "adapter and recorder ports must differ"
        );
        let origin: hyper::Uri = self.source_origin.parse()?;
        brz_http_gateway::AdmissionTicket::new("validation", "validation")?
            .with_origin(origin.clone())?;
        ensure!(
            origin.host().is_some_and(|host| host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())),
            "Source origin must be loopback-only"
        );
        ensure!(
            origin.port_u16().unwrap_or(80) != self.recorder_listen.port()
                && origin.port_u16().unwrap_or(80) != self.listen.port(),
            "Source port must differ from both HTTP listeners"
        );
        let mut config = if let Some(path) = &self.config_path {
            if let Some(policy) = &self.policy {
                let reference = crate::config::resolve_unified_policy_path(path)?;
                ensure!(
                    std::fs::canonicalize(policy)? == std::fs::canonicalize(reference)?,
                    "--policy must name the same file as project.policy when --config is supplied"
                );
            }
            AppConfig::load(path)?
        } else {
            let mut config = AppConfig::default();
            config.http_gateway.per_api_case_limits.default = usize::MAX;
            config.http_gateway.request_timeout_ms = 30_000;
            config.recording.encrypt_request_headers =
                vec!["authorization".to_owned(), "cookie".to_owned()];
            config.recording.redact_headers = vec!["proxy-authorization".to_owned()];
            config.recording.shutdown_case_drain_timeout_ms = 60_000;
            config.dns_mock.enabled = true;
            config.tcp_gateway.enabled = true;
            config.udp_gateway.enabled = true;
            config.udp_gateway.forward = true;
            config.dns_mock.upstream_dns = system_dns();
            if let Some(path) = &self.policy {
                SourceTrafficPolicyConfig::load(path)?.apply_to(&mut config)?;
            }
            config
        };
        config.artifacts = Some(ArtifactsConfig {
            root_dir: self.data_root.join(crate::repository::LOCAL_ARTIFACTS_ROOT),
        });
        config.http_gateway.enabled = true;
        config.http.enabled = false;
        config.http_gateway.listen = self.recorder_listen;
        config.http_gateway.matched_upstream = self.source_origin.clone();
        if let Some(seconds) = self.request_timeout_seconds {
            config.http_gateway.request_timeout_ms = seconds
                .checked_mul(1000)
                .context("request timeout too large")?;
        }
        config.http_gateway.fallback_mode = HttpGatewayFallbackMode::FixedResponse;
        config.http_gateway.fixed_response = Some(HttpGatewayFixedResponseConfig {
            status: 404,
            body: "recorder unavailable".to_owned(),
            ..Default::default()
        });
        config.http_gateway.ready.enabled = true;
        if let Some(path) = &self.ready_path {
            config.http_gateway.ready.path = path.clone();
        }
        if let Some(limit) = self.case_limit {
            config.http_gateway.per_api_case_limits.default = limit.get();
        }
        let recorder_data = self.data_root.join(crate::repository::LOCAL_DATA_ROOT);
        config.tls.ca_cert_path = recorder_data.join("traffic-recorder-ca.pem");
        config.tls.ca_key_path = recorder_data.join("traffic-recorder-ca-key.pem");
        if self.no_interception {
            config.dns_mock.enabled = false;
            config.tcp_gateway.enabled = false;
            config.udp_gateway.enabled = false;
            config.http_response_rewrite.enabled = false;
        } else {
            ensure!(
                config.dns_mock.enabled && config.tcp_gateway.enabled,
                "online interception requires enabled DNS and TCP gateways"
            );
        }
        if let Some(upstream) = self.dns_upstream {
            config.dns_mock.upstream_dns = upstream;
        }
        config.dns_mock.registry_path = self
            .data_root
            .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
            .join("fake_dns_registry.json");
        config
            .validate()
            .context("invalid recording service configuration")?;
        Ok(config)
    }
}

fn parse_run_id(value: &str) -> std::result::Result<String, String> {
    if value.len() == 14
        && value.bytes().all(|c| c.is_ascii_digit())
        && chrono::NaiveDateTime::parse_from_str(value, "%Y%m%d%H%M%S").is_ok()
    {
        Ok(value.to_owned())
    } else {
        Err("run ID must be a valid 14-digit UTC timestamp".to_owned())
    }
}

fn system_dns() -> SocketAddr {
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("nameserver ")
                    .and_then(|ip| ip.trim().parse::<std::net::IpAddr>().ok())
            })
        })
        .map(|ip| SocketAddr::new(ip, 53))
        .unwrap_or_else(|| "8.8.8.8:53".parse().unwrap())
}

impl std::fmt::Debug for RecordOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordOptions")
            .field("coordination", &self.coordination)
            .field("listen", &self.listen)
            .field("run_id", &self.run_id)
            .field("data_root", &self.data_root)
            .finish_non_exhaustive()
    }
}
