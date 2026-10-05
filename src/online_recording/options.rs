//! Parameters for a standalone recording service, without project or API policy files.

use crate::{AppConfig, ArtifactsConfig, HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig};
use anyhow::{Context, Result, ensure};
use brz_redis::{RedisService, RedisServiceOptions};
use clap::Args;
use std::{ffi::OsString, net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Args)]
pub struct OnlineRecordingOptions {
    #[arg(
        long,
        env = "TRAFFIC_E2E_ONLINE_LISTEN",
        default_value = "0.0.0.0:4080"
    )]
    pub listen: SocketAddr,
    /// Reachable HTTP origin published to gateways, including the exposed port.
    #[arg(long, env = "TRAFFIC_E2E_ONLINE_URL")]
    pub advertise_url: String,
    /// Coordination Redis URL. Falls back to the Source's REDIS_URL when omitted.
    #[arg(long, env = "TRAFFIC_E2E_RECORDING_REDIS_URL", hide_env_values = true)]
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
    #[arg(long, env = "TRAFFIC_E2E_SOURCE_READY_PATH", default_value = "/")]
    pub ready_path: String,
    #[arg(
        long,
        env = "TRAFFIC_E2E_DATA_ROOT",
        default_value = "/data/traffic-e2e"
    )]
    pub data_root: PathBuf,
    #[arg(long, env = "TRAFFIC_E2E_SOURCE_WORKDIR", default_value = "/app")]
    pub source_workdir: PathBuf,
    #[arg(long, env = "TRAFFIC_E2E_DNS_UPSTREAM")]
    pub dns_upstream: Option<SocketAddr>,
    #[arg(long, default_value = "300", value_parser = clap::value_parser!(u64).range(1..))]
    pub startup_timeout_seconds: u64,
    #[arg(long, default_value = "30", value_parser = clap::value_parser!(u64).range(1..))]
    pub request_timeout_seconds: u64,
    /// Maximum published cases per API pattern; default is effectively unlimited.
    #[arg(long, env = "TRAFFIC_E2E_CASE_LIMIT", default_value_t = std::num::NonZeroUsize::new(usize::MAX).unwrap())]
    pub case_limit: std::num::NonZeroUsize,
    /// Development only: disable fixed-identity DNS/fake-IP interception.
    #[arg(long)]
    pub no_interception: bool,
    #[arg(last = true, required = true, num_args = 1..)]
    pub source_command: Vec<OsString>,
}

impl OnlineRecordingOptions {
    pub fn initialize_storage(&mut self) -> Result<String> {
        std::fs::create_dir_all(&self.data_root)?;
        self.data_root = self.data_root.canonicalize()?;
        crate::source_recording::prepare_recordings_root(
            &self.data_root,
            crate::ArtifactOwner::invoking()?,
        )?;
        crate::platform::encryption_key::load_or_create(&self.data_root)
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
        let mut config = AppConfig {
            artifacts: Some(ArtifactsConfig {
                root_dir: self.data_root.join(crate::repository::LOCAL_ARTIFACTS_ROOT),
            }),
            ..AppConfig::default()
        };
        config.http_gateway.enabled = true;
        config.http.enabled = false;
        config.http_gateway.listen = self.recorder_listen;
        config.http_gateway.matched_upstream = self.source_origin.clone();
        config.http_gateway.request_timeout_ms = self
            .request_timeout_seconds
            .checked_mul(1000)
            .context("request timeout too large")?;
        config.http_gateway.fallback_mode = HttpGatewayFallbackMode::FixedResponse;
        config.http_gateway.fixed_response = Some(HttpGatewayFixedResponseConfig {
            status: 404,
            body: "recorder unavailable".to_owned(),
            ..Default::default()
        });
        config.http_gateway.ready.enabled = true;
        config.http_gateway.ready.path = self.ready_path.clone();
        config.http_gateway.per_api_case_limits.default = self.case_limit.get();
        config.recording.encrypt_request_headers =
            vec!["authorization".to_owned(), "cookie".to_owned()];
        config.recording.redact_headers = vec!["proxy-authorization".to_owned()];
        config.recording.shutdown_case_drain_timeout_ms = 60_000;
        config.tls.ca_cert_path = self.data_root.join("tls/recorder-ca.pem");
        config.tls.ca_key_path = self.data_root.join("tls/recorder-ca-key.pem");
        config.dns_mock.enabled = !self.no_interception;
        config.tcp_gateway.enabled = !self.no_interception;
        config.udp_gateway.enabled = !self.no_interception;
        config.udp_gateway.forward = true;
        config.dns_mock.upstream_dns = self.dns_upstream.unwrap_or_else(system_dns);
        config.dns_mock.registry_path = self.data_root.join("fake-dns-registry.json");
        Ok(config)
    }

    pub(super) async fn redis(&self) -> Result<RedisService> {
        let input = self
            .redis_url
            .clone()
            .or_else(|| std::env::var("REDIS_URL").ok())
            .context("provide --redis-url or REDIS_URL")?;
        let parsed = url::Url::parse(&input)
            .map_err(|_| anyhow::anyhow!("invalid coordination Redis URL"))?;
        ensure!(
            parsed.scheme() == "redis"
                && parsed.query().is_none()
                && parsed.fragment().is_none()
                && (parsed.username().is_empty() || parsed.username() == "default"),
            "Redis requires redis:// with password-only/default-user authentication and no query"
        );
        let host = parsed.host_str().context("Redis URL requires a host")?;
        let db = parsed.path().trim_start_matches('/');
        let db = if db.is_empty() {
            0
        } else {
            db.parse::<u32>()
                .context("Redis DB must be a nonnegative integer")?
        };
        let password = parsed.password().map(percent_decode).transpose()?;
        let endpoint = format!("{host}:{}:{db}", parsed.port().unwrap_or(6379));
        Ok(RedisService::single_with_options(
            endpoint,
            RedisServiceOptions::default()
                .with_password(password)
                .with_timeout(Duration::from_millis(200)),
        )
        .await?)
    }
}

fn percent_decode(value: &str) -> Result<String> {
    // URL form parsing already supplies percent decoding without another dependency.
    let encoded = format!("value={}", value.replace('+', "%2B"));
    Ok(url::form_urlencoded::parse(encoded.as_bytes())
        .next()
        .context("invalid Redis password")?
        .1
        .into_owned())
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
