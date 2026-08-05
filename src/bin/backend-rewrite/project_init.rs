use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use traffic_e2e::{
    DEFAULT_HTTP_GATEWAY_PORT, InspectedContainer, RepositoryConfigInitOptions,
    RepositoryConfigInitResult, initialize_repository_config,
};

#[derive(Debug, Args)]
pub(super) struct ProjectInitArgs {
    /// Existing genuine source application container to inspect and reproduce.
    #[arg(long)]
    source_container: String,
    /// Enable Breeze using the conventional `breeze` container, or provide a non-standard name.
    #[arg(long, num_args = 0..=1, default_missing_value = "breeze", value_name = "CONTAINER")]
    breeze: Option<String>,
    /// HTTP gateway port that receives traffic selected for recording.
    #[arg(long, default_value_t = DEFAULT_HTTP_GATEWAY_PORT)]
    pub(super) http_gateway_port: u16,
    /// Source HTTP port used by the managed recorder.
    #[arg(long, default_value_t = 8080)]
    source_http_port: u16,
    /// Target HTTP port used for replay and comparison.
    #[arg(long, default_value_t = 8081)]
    target_port: u16,
    /// Readiness path shared by source recording and target startup.
    #[arg(long, default_value = "/healthz")]
    readiness_path: String,
    /// Final HTTP status that indicates readiness.
    #[arg(long, default_value_t = 404)]
    readiness_status: u16,
    /// DNS server for queries not owned by the recorder.
    #[arg(long, default_value = "10.10.10.11:53")]
    upstream_dns: SocketAddr,
}

#[derive(Debug, Serialize)]
struct ProjectInitReport {
    generated: Vec<PathBuf>,
    source_container: InspectedContainer,
    #[serde(skip_serializing_if = "Option::is_none")]
    breeze_container: Option<InspectedContainer>,
    http_gateway_port: u16,
    local_dir: PathBuf,
    gitignore: PathBuf,
    gitignore_updated: bool,
    boot_dir: PathBuf,
    boot_dir_created: bool,
    target_start_contract: String,
    target_compile_contract: &'static str,
    target_stop_contract: String,
}

pub(super) fn run(target_root: PathBuf, args: ProjectInitArgs, pretty: bool) -> Result<()> {
    let result = initialize_repository_config(RepositoryConfigInitOptions {
        target_root,
        source_container: args.source_container,
        breeze_container: args.breeze,
        source_http_port: args.source_http_port,
        target_port: args.target_port,
        http_gateway_port: args.http_gateway_port,
        readiness_path: args.readiness_path,
        readiness_status: args.readiness_status,
        upstream_dns: args.upstream_dns,
    })?;
    super::print_json(&ProjectInitReport::from(result), pretty)
}

impl From<RepositoryConfigInitResult> for ProjectInitReport {
    fn from(result: RepositoryConfigInitResult) -> Self {
        Self {
            generated: result.generated,
            source_container: result.source_container,
            breeze_container: result.breeze_container,
            http_gateway_port: result.http_gateway_port,
            local_dir: result.local_dir,
            gitignore: result.gitignore,
            gitignore_updated: result.gitignore_updated,
            boot_dir: result.boot_dir,
            boot_dir_created: result.boot_dir_created,
            target_start_contract: result.target_start_contract,
            target_compile_contract: result.target_compile_contract,
            target_stop_contract: result.target_stop_contract,
        }
    }
}
