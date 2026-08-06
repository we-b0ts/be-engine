use std::ffi::OsStr;
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{ArgAction, Args};
use tracing::info;
use traffic_e2e::{
    AppConfig, AppState, ArtifactOwner, HttpResponseRewritePluginConfig, RecordingApi, TlsConfig,
};

use super::interception::{DnsConfig, FakeIpConfig, Guard};

#[derive(Debug, Args)]
pub(super) struct RecordArgs {
    /// Recorder TOML configuration.
    #[arg(long)]
    config: PathBuf,
    /// Explicit 14-digit UTC recording run identifier.
    #[arg(long, value_parser = parse_run_id)]
    run_id: Option<String>,
    /// Assign the finalized recording run to this numeric UID:GID.
    #[arg(long, value_name = "UID:GID")]
    artifact_owner: Option<ArtifactOwner>,
    /// Publish managed recording lifecycle state on this Unix socket.
    #[arg(long)]
    control_socket: Option<PathBuf>,
    /// Record only this API for the current run; repeat for multiple METHOD/path selectors.
    #[arg(long = "api", value_name = "METHOD PATH_OR_PATTERN")]
    apis: Vec<RecordingApi>,
    /// Override the per-API case limit for this run.
    #[arg(long = "per-api-case-limit", value_name = "N")]
    per_api_case_limit: Option<NonZeroUsize>,
    /// Enable fixed-user local DNS and fake-IP interception.
    #[arg(long, default_value_t = true, action = ArgAction::SetTrue, overrides_with = "no_dns")]
    dns: bool,
    /// Run the recorder without changing local DNS or iptables state.
    #[arg(long, action = ArgAction::SetTrue, overrides_with = "dns")]
    no_dns: bool,
}

pub(super) async fn run(args: RecordArgs) -> Result<()> {
    ensure!(
        args.config.is_file(),
        "recorder config not found: {}",
        args.config.display()
    );
    reject_owner_config(&args.config)?;
    if args.artifact_owner.is_some() {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "--artifact-owner requires traffic-e2e record to run as root"
        );
    }
    let mut config = AppConfig::load(&args.config)?;
    if let Some(per_api_case_limit) = args.per_api_case_limit {
        config.override_per_api_case_limit_for_run(per_api_case_limit);
    }
    config.dns_mock.fake_cidr = environment("FAKE_CIDR", &config.dns_mock.fake_cidr);
    preflight(&config)?;
    let configured_fake_cidr = config.dns_mock.fake_cidr.clone();
    let state = AppState::new_with_recording_apis_and_artifact_owner(
        config,
        args.run_id,
        args.apis,
        args.artifact_owner,
    )
    .await?;
    let mut interception = if args.dns && !args.no_dns {
        Some(Guard::enable(
            record_dns_config()?,
            record_fake_ip_config(&configured_fake_cidr)?,
        )?)
    } else {
        None
    };
    let result = state.run_with_control_socket(args.control_socket).await;
    if let Some(guard) = interception.as_mut() {
        guard.disable();
    }
    result
}

fn parse_run_id(value: &str) -> std::result::Result<String, String> {
    if value.len() == 14
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && chrono::NaiveDateTime::parse_from_str(value, "%Y%m%d%H%M%S").is_ok()
    {
        Ok(value.to_string())
    } else {
        Err("run ID must contain exactly 14 ASCII digits (YYYYMMDDHHMMSS)".to_string())
    }
}

fn preflight(config: &AppConfig) -> Result<()> {
    check_plugin_commands(config, std::env::var_os("PATH").as_deref())?;
    if check_ca_files(&config.tls)? {
        info!(
            ca_cert_path = %config.tls.ca_cert_path.display(),
            ca_key_path = %config.tls.ca_key_path.display(),
            "MITM CA files not found; Recorder will generate them"
        );
    }
    Ok(())
}

fn check_plugin_commands(config: &AppConfig, search_path: Option<&OsStr>) -> Result<()> {
    if !config.http_response_rewrite.enabled {
        return Ok(());
    }

    for rule in &config.http_response_rewrite.rules {
        match &rule.plugin {
            HttpResponseRewritePluginConfig::PlutoEciKubeconfig { kubectl_binary, .. } => {
                require_executable(kubectl_binary, search_path).with_context(|| {
                    format!(
                        "HTTP response rewrite rule {:?} plugin \"pluto-eci-kubeconfig\" requires \
                         kubectl_binary {:?}; install kubectl or configure kubectl_binary with an \
                         executable path",
                        rule.name, kubectl_binary
                    )
                })?;
            }
            HttpResponseRewritePluginConfig::VintageNaming { .. }
            | HttpResponseRewritePluginConfig::VintageCacheConfig => {}
        }
    }
    Ok(())
}

fn require_executable(command: &str, search_path: Option<&OsStr>) -> Result<()> {
    let configured = Path::new(command);
    let resolved = if configured.components().count() > 1 {
        configured.to_path_buf()
    } else {
        search_path
            .and_then(|value| {
                std::env::split_paths(value)
                    .map(|directory| directory.join(configured))
                    .find(|candidate| {
                        fs::metadata(candidate)
                            .is_ok_and(|metadata| metadata_is_executable(&metadata))
                    })
            })
            .with_context(|| format!("executable command {command:?} was not found on PATH"))?
    };
    let metadata = fs::metadata(&resolved)
        .with_context(|| format!("failed to inspect command {}", resolved.display()))?;
    ensure!(
        metadata.is_file(),
        "command is not a regular file: {}",
        resolved.display()
    );
    ensure!(
        metadata_is_executable(&metadata),
        "command is not executable: {}",
        resolved.display()
    );
    Ok(())
}

fn metadata_is_executable(metadata: &fs::Metadata) -> bool {
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn check_ca_files(tls: &TlsConfig) -> Result<bool> {
    ensure!(
        tls.ca_cert_path != tls.ca_key_path,
        "MITM CA certificate and private key paths must be different: {}",
        tls.ca_cert_path.display()
    );
    let cert_exists = tls.ca_cert_path.try_exists().with_context(|| {
        format!(
            "failed to inspect MITM CA certificate {}",
            tls.ca_cert_path.display()
        )
    })?;
    let key_exists = tls.ca_key_path.try_exists().with_context(|| {
        format!(
            "failed to inspect MITM CA private key {}",
            tls.ca_key_path.display()
        )
    })?;
    match (cert_exists, key_exists) {
        (true, true) => {
            ensure!(
                tls.ca_cert_path.is_file(),
                "MITM CA certificate is not a regular file: {}",
                tls.ca_cert_path.display()
            );
            ensure!(
                tls.ca_key_path.is_file(),
                "MITM CA private key is not a regular file: {}",
                tls.ca_key_path.display()
            );
            Ok(false)
        }
        (false, false) => Ok(true),
        (true, false) => bail!(
            "MITM CA certificate exists but its private key is missing: {}\n\
             Restore the matching key or remove the certificate so Recorder can generate a new CA pair.",
            tls.ca_key_path.display()
        ),
        (false, true) => bail!(
            "MITM CA private key exists but its certificate is missing: {}\n\
             Restore the matching certificate or remove the private key so Recorder can generate a new CA pair.",
            tls.ca_cert_path.display()
        ),
    }
}

fn reject_owner_config(path: &PathBuf) -> Result<()> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read recorder config {}", path.display()))?;
    let config: toml::Value = toml::from_str(&source)
        .with_context(|| format!("failed to parse recorder config {}", path.display()))?;
    let forbidden = ["owner_uid", "user", "record_user", "all_users"]
        .into_iter()
        .filter(|name| {
            config
                .get("local_record")
                .and_then(toml::Value::as_table)
                .is_some_and(|local| local.contains_key(*name))
        })
        .collect::<Vec<_>>();
    ensure!(
        forbidden.is_empty(),
        "unsupported local_record owner settings: {}; interception always uses the \
         recorder-owned fixed user",
        forbidden.join(", ")
    );
    Ok(())
}

fn record_dns_config() -> Result<DnsConfig> {
    Ok(DnsConfig {
        dns_ip: environment("DNS_IP", "127.0.0.153"),
        dns_port: environment("DNS_PORT", "15353")
            .parse()
            .context("DNS_PORT must be a valid port")?,
    })
}

fn record_fake_ip_config(configured_fake_cidr: &str) -> Result<FakeIpConfig> {
    Ok(FakeIpConfig {
        fake_cidr: environment("FAKE_CIDR", configured_fake_cidr),
        tcp_port: environment("GATEWAY_PORT", "15001")
            .parse()
            .context("GATEWAY_PORT must be a valid port")?,
        udp_port: environment("UDP_GATEWAY_PORT", "15002")
            .parse()
            .context("UDP_GATEWAY_PORT must be a valid port")?,
        tcp: true,
        udp: parse_bool_environment("ENABLE_UDP", true)?,
    })
}

fn environment(name: &str, default: &str) -> String {
    let value = std::env::var(name).ok();
    resolve_environment_config_default(value.as_deref(), default)
}

fn resolve_environment_config_default(
    environment_value: Option<&str>,
    configured_value: &str,
) -> String {
    environment_value.unwrap_or(configured_value).to_string()
}

fn parse_bool_environment(name: &str, default: bool) -> Result<bool> {
    match std::env::var(name) {
        Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => Ok(true),
        Ok(value) if value == "0" || value.eq_ignore_ascii_case("false") => Ok(false),
        Ok(value) => anyhow::bail!("{name} must be 0, 1, true, or false; got {value:?}"),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use clap::Parser;
    use traffic_e2e::DEFAULT_FAKE_CIDR;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        record: RecordArgs,
    }

    #[test]
    fn accepts_only_valid_explicit_run_ids() {
        let cli = TestCli::try_parse_from([
            "test",
            "--config",
            "recorder.toml",
            "--run-id",
            "20260721153045",
        ])
        .unwrap();
        assert_eq!(cli.record.run_id.as_deref(), Some("20260721153045"));

        assert!(
            TestCli::try_parse_from([
                "test",
                "--config",
                "recorder.toml",
                "--run-id",
                "20260230153045",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "--config",
                "recorder.toml",
                "--run-id",
                "../../recording",
            ])
            .is_err()
        );
    }

    #[test]
    fn accepts_only_numeric_artifact_owners() {
        let cli = TestCli::try_parse_from([
            "test",
            "--config",
            "recorder.toml",
            "--artifact-owner",
            "1114:1115",
        ])
        .unwrap();

        assert_eq!(
            cli.record.artifact_owner,
            Some(ArtifactOwner::new(1114, 1115))
        );
        for invalid in ["icy:icy", "1114", "1114:", "-1:1115"] {
            assert!(
                TestCli::try_parse_from([
                    "test",
                    "--config",
                    "recorder.toml",
                    "--artifact-owner",
                    invalid,
                ])
                .is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn accepts_recording_control_socket() {
        let cli = TestCli::try_parse_from([
            "test",
            "--config",
            "recorder.toml",
            "--control-socket",
            "/run/traffic-e2e/recording.sock",
        ])
        .unwrap();

        assert_eq!(
            cli.record.control_socket.as_deref(),
            Some(Path::new("/run/traffic-e2e/recording.sock"))
        );
    }

    #[test]
    fn accepts_repeatable_runtime_api_selection() {
        let cli = TestCli::try_parse_from([
            "test",
            "--config",
            "recorder.toml",
            "--api",
            "GET /api/users/*",
            "--api",
            "HEAD /healthz",
        ])
        .unwrap();

        assert_eq!(
            cli.record
                .apis
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["GET /api/users/*", "HEAD /healthz"]
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "--config",
                "recorder.toml",
                "--api",
                "get /api/users",
            ])
            .is_err()
        );
    }

    #[test]
    fn accepts_only_positive_per_api_case_limits() {
        let cli = TestCli::try_parse_from([
            "test",
            "--config",
            "recorder.toml",
            "--per-api-case-limit",
            "250",
        ])
        .unwrap();

        assert_eq!(
            cli.record.per_api_case_limit.map(NonZeroUsize::get),
            Some(250)
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "--config",
                "recorder.toml",
                "--per-api-case-limit",
                "0",
            ])
            .is_err()
        );
    }

    #[test]
    fn no_dns_overrides_default_interception() {
        let default = TestCli::try_parse_from(["test", "--config", "recorder.toml"]).unwrap();
        assert!(default.record.dns);
        assert!(!default.record.no_dns);

        let cli =
            TestCli::try_parse_from(["test", "--config", "recorder.toml", "--no-dns"]).unwrap();
        assert!(cli.record.no_dns);
    }

    #[test]
    fn fake_cidr_precedence_is_environment_then_config_then_default() {
        let configured: AppConfig = toml::from_str(
            r#"
            [dns_mock]
            fake_cidr = "198.19.64.0/18"
            "#,
        )
        .unwrap();
        let defaults = AppConfig::default();

        assert_eq!(
            resolve_environment_config_default(
                Some("198.19.128.0/17"),
                &configured.dns_mock.fake_cidr,
            ),
            "198.19.128.0/17"
        );
        assert_eq!(
            resolve_environment_config_default(None, &configured.dns_mock.fake_cidr),
            "198.19.64.0/18"
        );
        assert_eq!(
            resolve_environment_config_default(None, &defaults.dns_mock.fake_cidr),
            DEFAULT_FAKE_CIDR
        );
    }

    #[test]
    fn interception_dns_uses_local_listener_only() {
        let interception = record_dns_config().unwrap();

        assert_eq!(interception.dns_ip, "127.0.0.153");
        assert_eq!(interception.dns_port, 15353);
    }

    #[test]
    fn rejects_configurable_interception_owner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("recorder.toml");
        std::fs::write(&path, "[local_record]\nowner_uid = 1000\n").unwrap();

        let error = reject_owner_config(&path).unwrap_err().to_string();

        assert!(error.contains("owner_uid"));
        assert!(error.contains("fixed user"));
    }

    #[test]
    fn reports_missing_enabled_plugin_command_with_install_guidance() {
        let config: AppConfig = toml::from_str(
            r#"
            [http_response_rewrite]
            enabled = true

            [[http_response_rewrite.rules]]
            name = "pluto-kubeconfig"
            authorities = ["cs.aliyuncs.com"]
            path = "/api/v2/k8s/cluster/user_config"
            plugin = { name = "pluto-eci-kubeconfig", kubectl_binary = "missing-kubectl", proxy_listen = "127.0.0.1:8001" }
            "#,
        )
        .unwrap();

        let error =
            check_plugin_commands(&config, Some(OsStr::new("/definitely-missing"))).unwrap_err();
        let message = format!("{error:?}");

        assert!(message.contains("pluto-kubeconfig"));
        assert!(message.contains("missing-kubectl"));
        assert!(message.contains("install kubectl"));
        assert!(message.contains("not found on PATH"));
    }

    #[test]
    fn accepts_executable_plugin_command_at_configured_path() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let command = directory.path().join("kubectl");
        fs::write(&command, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&command, fs::Permissions::from_mode(0o700)).unwrap();

        require_executable(command.to_str().unwrap(), None).unwrap();
    }

    #[test]
    fn treats_absent_ca_pair_as_automatically_generated() {
        let directory = tempfile::tempdir().unwrap();
        let tls = TlsConfig {
            ca_cert_path: directory.path().join("ca.pem"),
            ca_key_path: directory.path().join("ca-key.pem"),
        };

        assert!(check_ca_files(&tls).unwrap());
    }

    #[test]
    fn rejects_partial_ca_pair_with_recovery_guidance() {
        let directory = tempfile::tempdir().unwrap();
        let tls = TlsConfig {
            ca_cert_path: directory.path().join("ca.pem"),
            ca_key_path: directory.path().join("ca-key.pem"),
        };
        fs::write(&tls.ca_cert_path, "certificate").unwrap();

        let error = check_ca_files(&tls).unwrap_err().to_string();

        assert!(error.contains("private key is missing"));
        assert!(error.contains("generate a new CA pair"));
    }
}
