use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use clap::Args;
use traffic_e2e::{AppConfig, AppState, BackgroundDependencyRuleConfig, TrafficJsonlMode};

use super::interception::CachePortGuard;

#[derive(Debug, Args)]
pub(super) struct CacheSnapshotRunArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    control_socket: PathBuf,
}

pub(super) async fn run(args: CacheSnapshotRunArgs) -> Result<()> {
    ensure!(
        args.config.is_file(),
        "cache snapshot config not found: {}",
        args.config.display()
    );
    let mut config = AppConfig::load(&args.config)?;
    let ports = configure_runtime(&mut config, &args.output_dir);

    let state =
        AppState::new_with_recording_options(config, Some(args.run_id), Vec::new(), None, None)
            .await?;
    let ports = ports.into_iter().collect::<Vec<_>>();
    let tcp_port = state.config().tcp_gateway.listen.port();
    let mut interception = CachePortGuard::enable(&ports, tcp_port)?;
    let result = state
        .run_with_control_socket(Some(args.control_socket))
        .await;
    interception.disable();
    result
}

fn configure_runtime(config: &mut AppConfig, output_dir: &Path) -> BTreeSet<u16> {
    config.artifacts = None;
    config.recording.output_dir = output_dir.to_path_buf();
    config.recording.traffic_jsonl = TrafficJsonlMode::Errors;
    config.http.enabled = false;
    config.dns_mock.enabled = false;
    // The cache-snapshot container does not mount the Breeze snapshot
    // directory, and the run only captures background Redis dependencies, so
    // drop any Breeze bypass strategies to avoid loading a snapshot that is
    // unavailable in this container.
    config.dns_mock.bypass_strategies.clear();
    config.udp_gateway.enabled = false;
    config.mysql.enabled = false;
    // The cache-snapshot run captures only background Redis dependencies; it
    // does not perform HTTP interception or response rewriting. Disabling
    // dns_mock and tcp_gateway.record_http below would otherwise violate the
    // AppConfig validation requiring those to be enabled whenever
    // http_response_rewrite is enabled, so disable it here too.
    config.http_response_rewrite.enabled = false;
    // The HTTP gateway readiness probe closes the bootstrap dependency window,
    // so keep that probe enabled. Its listener is not part of cache snapshot
    // interception, though, and must not claim the externally configured
    // comparison gateway port before comparison recording starts.
    config.http_gateway.listen = SocketAddr::from(([127, 0, 0, 1], 0));
    config.tcp_gateway.enabled = true;
    config.tcp_gateway.record_http = false;
    config.tcp_gateway.mitm_https = false;
    config.tcp_gateway.protocol_detection.enabled = true;
    let ports = config
        .recording
        .background_dependencies
        .iter()
        .flat_map(|rule| match rule {
            BackgroundDependencyRuleConfig::Redis { ports, .. } => ports.clone(),
            _ => Vec::new(),
        })
        .collect::<BTreeSet<_>>();
    for port in &ports {
        if !config
            .tcp_gateway
            .protocol_detection
            .redis_port_hints
            .contains(port)
        {
            config
                .tcp_gateway
                .protocol_detection
                .redis_port_hints
                .push(*port);
        }
    }
    config.tls.ca_cert_path = output_dir.join("cache-snapshot-ca.pem");
    config.tls.ca_key_path = output_dir.join("cache-snapshot-ca-key.pem");
    config.dns_mock.registry_path = output_dir.join("cache-snapshot-dns.json");
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolates_snapshot_listener_from_comparison_gateway_port() {
        let mut config = AppConfig::default();
        config.http_gateway.enabled = true;
        config.http_gateway.ready.enabled = true;
        config.http_gateway.listen = SocketAddr::from(([0, 0, 0, 0], 18_062));

        configure_runtime(&mut config, Path::new("/tmp/cache-snapshot-test"));

        assert!(config.http_gateway.enabled);
        assert!(config.http_gateway.ready.enabled);
        assert_eq!(
            config.http_gateway.listen,
            SocketAddr::from(([127, 0, 0, 1], 0))
        );
        assert!(config.tcp_gateway.enabled);
        assert!(!config.tcp_gateway.record_http);
    }
}
