use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::{ArgAction, Args};
use serde::Deserialize;
use traffic_e2e::{
    AppConfig, DEFAULT_FAKE_CIDR, ReplayAllowedUnusedHttpConfig, ReplayConfig, run_replay,
};
use uuid::Uuid;

use super::interception::{DnsConfig, FakeIpConfig, Guard};
use super::signal::shutdown_signal;

const DEFAULT_DNS_LISTEN: &str = "127.0.0.153:15353";
const DEFAULT_TCP_LISTEN: &str = "127.0.0.1:15001";

#[derive(Debug, Args)]
pub(super) struct ReplayArgs {
    /// Published case or case-collection directory.
    #[arg(value_name = "CASE_OR_COLLECTION_DIR")]
    case: Option<PathBuf>,
    /// Optional replay launcher TOML configuration.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Enable fixed-user local interception.
    #[arg(long, action = ArgAction::SetTrue, overrides_with = "no_intercept")]
    intercept: bool,
    /// Start replay listeners without changing local DNS or iptables state.
    #[arg(long, action = ArgAction::SetTrue, overrides_with = "intercept")]
    no_intercept: bool,
    /// Replay only this published case. Repeat for a case set.
    #[arg(long = "case-id")]
    case_ids: Vec<String>,
    #[arg(long)]
    report: Option<PathBuf>,
    #[arg(long)]
    session: Option<PathBuf>,
    #[arg(long)]
    control_socket: Option<PathBuf>,
    #[arg(long)]
    dns_listen: Option<SocketAddr>,
    #[arg(long)]
    tcp_listen: Option<SocketAddr>,
    #[arg(long)]
    fake_cidr: Option<String>,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    recorder_config: Option<PathBuf>,
    #[arg(long, requires = "recorder_config")]
    recording_rule: Option<String>,
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    #[arg(long)]
    ca_key: Option<PathBuf>,
    #[arg(long = "http-ignore-query-param")]
    http_ignore_query_params: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ReplayFile {
    replay: ReplayFileValues,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ReplayFileValues {
    case: Option<PathBuf>,
    dns_listen: Option<SocketAddr>,
    tcp_listen: Option<SocketAddr>,
    fake_cidr: Option<String>,
    report: Option<PathBuf>,
    session: Option<PathBuf>,
    control_socket: Option<PathBuf>,
    enable_intercept: Option<bool>,
    policy: Option<PathBuf>,
    owner_uid: Option<toml::Value>,
    user: Option<toml::Value>,
    record_user: Option<toml::Value>,
    all_users: Option<toml::Value>,
}

struct ResolvedReplay {
    case: PathBuf,
    case_ids: Vec<String>,
    report: PathBuf,
    session: PathBuf,
    control_socket: PathBuf,
    dns_listen: SocketAddr,
    tcp_listen: SocketAddr,
    fake_cidr: String,
    intercept: bool,
    policy: Option<PathBuf>,
    recorder_config: Option<PathBuf>,
    recording_rule: Option<String>,
    ca_cert: Option<PathBuf>,
    ca_key: Option<PathBuf>,
    http_ignore_query_params: Vec<String>,
}

pub(super) async fn run(args: ReplayArgs) -> Result<()> {
    let resolved = resolve(args)?;
    let allowed_unused_http = load_allowed_unused_http(
        resolved.recorder_config.clone(),
        resolved.recording_rule.clone(),
    )?;
    let background_dependencies =
        load_background_dependencies(resolved.recorder_config.as_deref())?;
    let mut interception = if resolved.intercept {
        Some(Guard::enable_replay(
            DnsConfig {
                dns_ip: resolved.dns_listen.ip().to_string(),
                dns_port: resolved.dns_listen.port(),
            },
            FakeIpConfig {
                fake_cidr: resolved.fake_cidr.clone(),
                tcp_port: resolved.tcp_listen.port(),
                udp_port: 15002,
                tcp: true,
                udp: false,
            },
        )?)
    } else {
        None
    };
    let replay = run_replay(ReplayConfig {
        case_dir: resolved.case,
        selected_case_ids: resolved.case_ids,
        dns_listen: resolved.dns_listen,
        tcp_listen: resolved.tcp_listen,
        fake_cidr: resolved.fake_cidr,
        report_path: Some(resolved.report),
        session_path: Some(resolved.session),
        control_socket_path: Some(resolved.control_socket),
        ca_cert_path: resolved.ca_cert,
        ca_key_path: resolved.ca_key,
        policy_path: resolved.policy,
        http_ignore_query_params: resolved.http_ignore_query_params,
        background_dependencies,
        allowed_unused_http,
    });
    tokio::pin!(replay);
    let result = tokio::select! {
        result = &mut replay => result,
        signal = shutdown_signal() => {
            signal?;
            Ok(())
        }
    };
    if let Some(guard) = interception.as_mut() {
        guard.disable();
    }
    result
}

fn resolve(args: ReplayArgs) -> Result<ResolvedReplay> {
    let cwd = std::env::current_dir().context("failed to read current directory")?;
    let (file, config_dir) = match args.config.as_deref() {
        Some(path) => {
            let path = absolute_from(&cwd, path);
            ensure!(
                path.is_file(),
                "replay config not found: {}",
                path.display()
            );
            let source = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read replay config {}", path.display()))?;
            let file: ReplayFile = toml::from_str(&source)
                .with_context(|| format!("failed to parse replay config {}", path.display()))?;
            reject_file_owner(&file.replay)?;
            let parent = path
                .parent()
                .context("replay config has no parent directory")?
                .to_path_buf();
            (file, parent)
        }
        None => (ReplayFile::default(), cwd.clone()),
    };
    let case = args
        .case
        .map(|path| absolute_from(&cwd, &path))
        .or_else(|| {
            file.replay
                .case
                .as_deref()
                .map(|path| absolute_from(&config_dir, path))
        })
        .context("case directory is required")?;
    ensure!(
        case.is_dir(),
        "case directory not found: {}",
        case.display()
    );
    let dns_listen = args
        .dns_listen
        .or(file.replay.dns_listen)
        .unwrap_or(DEFAULT_DNS_LISTEN.parse()?);
    let intercept = if args.no_intercept {
        false
    } else if args.intercept {
        true
    } else {
        file.replay.enable_intercept.unwrap_or(true)
    };
    ensure!(
        !intercept || dns_listen.is_ipv4(),
        "local DNS interception currently requires an IPv4 listener"
    );
    let tcp_listen = args
        .tcp_listen
        .or(file.replay.tcp_listen)
        .unwrap_or(DEFAULT_TCP_LISTEN.parse()?);
    let fake_cidr = args
        .fake_cidr
        .or(file.replay.fake_cidr)
        .unwrap_or_else(|| DEFAULT_FAKE_CIDR.to_string());
    let report = match args.report {
        Some(path) => absolute_from(&cwd, &path),
        None => match file.replay.report.as_deref() {
            Some(path) => absolute_from(&config_dir, path),
            None => unique_report_path(&case)?,
        },
    };
    let session = match args.session {
        Some(path) => absolute_from(&cwd, &path),
        None => file
            .replay
            .session
            .as_deref()
            .map(|path| absolute_from(&config_dir, path))
            .unwrap_or_else(|| cwd.join(".replay/session.json")),
    };
    let control_socket = match args.control_socket {
        Some(path) => absolute_from(&cwd, &path),
        None => file
            .replay
            .control_socket
            .as_deref()
            .map(|path| absolute_from(&config_dir, path))
            .unwrap_or_else(|| {
                session
                    .parent()
                    .unwrap_or(cwd.as_path())
                    .join("control.sock")
            }),
    };
    let policy = match args.policy {
        Some(path) => Some(absolute_from(&cwd, &path)),
        None => file
            .replay
            .policy
            .as_deref()
            .map(|path| absolute_from(&config_dir, path)),
    };
    if let Some(path) = policy.as_deref() {
        ensure!(
            path.is_file(),
            "replay policy not found: {}",
            path.display()
        );
    }
    let recorder_config = args.recorder_config.map(|path| absolute_from(&cwd, &path));
    if let Some(path) = recorder_config.as_deref() {
        ensure!(
            path.is_file(),
            "recorder config not found: {}",
            path.display()
        );
    }
    ensure!(
        recorder_config.is_some() == args.recording_rule.is_some(),
        "--recorder-config and --recording-rule must be provided together"
    );
    Ok(ResolvedReplay {
        case,
        case_ids: args.case_ids,
        report,
        session,
        control_socket,
        dns_listen,
        tcp_listen,
        fake_cidr,
        intercept,
        policy,
        recorder_config,
        recording_rule: args.recording_rule,
        ca_cert: args.ca_cert.map(|path| absolute_from(&cwd, &path)),
        ca_key: args.ca_key.map(|path| absolute_from(&cwd, &path)),
        http_ignore_query_params: args.http_ignore_query_params,
    })
}

fn reject_file_owner(values: &ReplayFileValues) -> Result<()> {
    let forbidden = [
        ("owner_uid", values.owner_uid.as_ref()),
        ("user", values.user.as_ref()),
        ("record_user", values.record_user.as_ref()),
        ("all_users", values.all_users.as_ref()),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|_| name))
    .collect::<Vec<_>>();
    ensure!(
        forbidden.is_empty(),
        "unsupported replay owner settings: {}; interception always uses the recorder-owned \
         fixed user",
        forbidden.join(", ")
    );
    Ok(())
}

fn unique_report_path(case: &Path) -> Result<PathBuf> {
    let directory = case
        .join(".replay/sessions")
        .join(format!("session.{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&directory).with_context(|| {
        format!(
            "failed to create replay report directory {}",
            directory.display()
        )
    })?;
    Ok(directory.join("replay-report.json"))
}

fn absolute_from(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn load_allowed_unused_http(
    recorder_config: Option<PathBuf>,
    recording_rule: Option<String>,
) -> Result<Option<ReplayAllowedUnusedHttpConfig>> {
    let (Some(config_path), Some(recording_rule)) = (recorder_config, recording_rule) else {
        return Ok(None);
    };
    let config_path = config_path.canonicalize()?;
    let config = AppConfig::load(&config_path)?;
    let matches = config
        .http_gateway
        .rules
        .iter()
        .filter(|rule| rule.name.as_deref() == Some(recording_rule.as_str()))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "expected exactly one [[http_gateway.rules]] entry named {:?}, found {}",
        recording_rule,
        matches.len()
    );
    Ok(Some(ReplayAllowedUnusedHttpConfig {
        config_path,
        recording_rule,
        hosts: matches[0]
            .allowed_unused_http_hosts
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
    }))
}

fn load_background_dependencies(
    recorder_config: Option<&Path>,
) -> Result<Vec<traffic_e2e::BackgroundDependencyRuleConfig>> {
    recorder_config
        .map(|path| AppConfig::load(path).map(|config| config.recording.background_dependencies))
        .transpose()
        .map(Option::unwrap_or_default)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        replay: ReplayArgs,
    }

    #[test]
    fn interception_flags_preserve_config_fallback() {
        let default = TestCli::try_parse_from(["test", "cases"]).unwrap();
        assert!(!default.replay.intercept);
        assert!(!default.replay.no_intercept);

        let disabled = TestCli::try_parse_from(["test", "--no-intercept", "cases"]).unwrap();
        assert!(disabled.replay.no_intercept);
        assert!(!disabled.replay.intercept);
    }

    #[test]
    fn rejects_configurable_replay_owner() {
        let file: ReplayFile = toml::from_str("[replay]\nowner_uid = 1000\n").unwrap();
        let error = reject_file_owner(&file.replay).unwrap_err().to_string();
        assert!(error.contains("owner_uid"));
        assert!(error.contains("fixed user"));
    }

    #[test]
    fn replay_file_rejects_unknown_fields() {
        assert!(toml::from_str::<ReplayFile>("[replay]\nunknown = true\n").is_err());
    }

    #[test]
    fn rejects_removed_upstream_dns_setting() {
        assert!(
            TestCli::try_parse_from(["test", "--upstream-dns", "10.10.10.10:53", "cases"]).is_err()
        );
        assert!(
            toml::from_str::<ReplayFile>("[replay]\nupstream_dns = \"10.10.10.10:53\"\n").is_err()
        );
    }

    #[test]
    fn replay_file_paths_are_relative_to_the_config() {
        let directory = tempfile::tempdir().unwrap();
        let config_dir = directory.path().join("config");
        let case_dir = directory.path().join("cases");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&case_dir).unwrap();
        let config = config_dir.join("replay.toml");
        std::fs::write(
            &config,
            "[replay]\ncase = \"../cases\"\nenable_intercept = false\n",
        )
        .unwrap();

        let resolved = resolve(replay_args(None, Some(config))).unwrap();

        assert_eq!(
            resolved.case.canonicalize().unwrap(),
            case_dir.canonicalize().unwrap()
        );
        assert!(!resolved.intercept);
    }

    #[test]
    fn no_intercept_accepts_an_ipv6_dns_listener() {
        let directory = tempfile::tempdir().unwrap();
        let mut args = replay_args(Some(directory.path().to_path_buf()), None);
        args.no_intercept = true;
        args.dns_listen = Some("[::1]:15353".parse().unwrap());

        assert!(resolve(args).is_ok());
    }

    fn replay_args(case: Option<PathBuf>, config: Option<PathBuf>) -> ReplayArgs {
        ReplayArgs {
            case,
            config,
            intercept: false,
            no_intercept: false,
            case_ids: Vec::new(),
            report: None,
            session: None,
            control_socket: None,
            dns_listen: None,
            tcp_listen: None,
            fake_cidr: None,
            policy: None,
            recorder_config: None,
            recording_rule: None,
            ca_cert: None,
            ca_key: None,
            http_ignore_query_params: Vec::new(),
        }
    }
}
