use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::{ArgAction, Args};
use traffic_e2e::{AppConfig, AppState};

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
}
