use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{ArgAction, Args};
use tracing::info;
use traffic_e2e::{AppConfig, AppState, HttpResponseRewritePluginConfig, TlsConfig};

use super::interception::{DnsConfig, FakeIpConfig, Guard};

#[derive(Debug, Args)]
pub(super) struct RecordArgs {
    /// Recorder TOML configuration.
    #[arg(long)]
    config: PathBuf,
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
    let config = AppConfig::load(&args.config)?;
    preflight(&config)?;
    let state = AppState::new(config).await?;
    let mut interception = if args.dns && !args.no_dns {
        Some(Guard::enable(
            record_dns_config()?,
            record_fake_ip_config()?,
        )?)
    } else {
        None
    };
    let result = state.run().await;
    if let Some(guard) = interception.as_mut() {
        guard.disable();
    }
    result
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
        upstream_dns: environment("UPSTREAM_DNS", "10.10.10.10:53")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
    })
}

fn record_fake_ip_config() -> Result<FakeIpConfig> {
    Ok(FakeIpConfig {
        fake_cidr: environment("FAKE_CIDR", "198.18.0.0/15"),
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
    std::env::var(name).unwrap_or_else(|_| default.to_string())
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

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        record: RecordArgs,
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
