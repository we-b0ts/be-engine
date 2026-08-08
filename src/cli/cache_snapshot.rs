use std::collections::BTreeSet;
use std::path::PathBuf;

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
    config.artifacts = None;
    config.recording.output_dir = args.output_dir.clone();
    config.recording.traffic_jsonl = TrafficJsonlMode::Errors;
    config.http.enabled = false;
    config.dns_mock.enabled = false;
    config.udp_gateway.enabled = false;
    config.mysql.enabled = false;
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
    config.tls.ca_cert_path = args.output_dir.join("cache-snapshot-ca.pem");
    config.tls.ca_key_path = args.output_dir.join("cache-snapshot-ca-key.pem");
    config.dns_mock.registry_path = args.output_dir.join("cache-snapshot-dns.json");

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
