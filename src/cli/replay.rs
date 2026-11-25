use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::{ArgAction, Args};
use serde::Deserialize;
use traffic_e2e::{
    AppConfig, DEFAULT_DNS_MOCK_LISTEN, DEFAULT_FAKE_CIDR, DEFAULT_TCP_GATEWAY_LISTEN,
    DEFAULT_UDP_GATEWAY_PORT, RecordingApi, ReplayAllowedUnusedHttpConfig, ReplayConfig,
    ReplayLifecycleConfig, ReplayTimerConfig, resolve_recording_api_case_ids,
    run_replay_with_timer_config, run_session_replay,
};
use uuid::Uuid;

use super::interception::{DnsConfig, FakeIpConfig, Guard};
use super::signal::shutdown_signal;

#[derive(Debug, Args)]
pub(super) struct ReplayArgs {
    /// Continue through supported tentative value rules while retaining dirty evidence.
    #[arg(long)]
    pre_match: bool,
    /// Set stream timing for Case Replay. Session Replay always runs without recorded waits.
    #[arg(long, value_enum)]
    stream_timing: Option<traffic_e2e::ReplayStreamTiming>,
    /// Maximum Case HTTP stream or Pub/Sub gap in fast mode, in milliseconds (default: 5).
    #[arg(long)]
    stream_interval_cap_ms: Option<u64>,
    /// Published Case, collection, or sealed recording session directory.
    #[arg(value_name = "CASE_OR_COLLECTION_DIR")]
    case: Option<PathBuf>,
    /// Replay the complete session event stream, starting at process launch.
    #[arg(long, conflicts_with_all = ["apis", "case_ids", "pre_match"])]
    session_events: bool,
    /// Optional replay launcher TOML configuration.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Enable fixed-user local interception.
    #[arg(long, action = ArgAction::SetTrue, overrides_with = "no_intercept")]
    intercept: bool,
    /// Start replay listeners without changing local DNS or iptables state.
    #[arg(long, action = ArgAction::SetTrue, overrides_with = "intercept")]
    no_intercept: bool,
    /// Replay every published case belonging to this API. Repeat for an API set.
    #[arg(
        long = "api",
        value_name = "METHOD path-or-pattern",
        conflicts_with = "case_ids"
    )]
    apis: Vec<RecordingApi>,
    /// Replay only this published case. Repeat for a case set.
    #[arg(long = "case-id")]
    case_ids: Vec<String>,
    #[arg(long)]
    report: Option<PathBuf>,
    #[arg(long)]
    session: Option<PathBuf>,
    #[arg(long)]
    control_socket: Option<PathBuf>,
    /// JSON plan attaching Target timer waits to recorded request events.
    #[arg(long, requires = "timer_socket")]
    timer_plan: Option<PathBuf>,
    /// Dedicated Unix socket for the Target timer SDK.
    #[arg(long, requires = "timer_plan")]
    timer_socket: Option<PathBuf>,
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
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    #[arg(long)]
    ca_key: Option<PathBuf>,
    #[arg(long = "http-ignore-query-param")]
    http_ignore_query_params: Vec<String>,
    /// Keep the active case open for dependencies started just after the primary response.
    #[arg(long)]
    case_dependency_post_response_window_ms: Option<u64>,
    /// Fail only this Case after this much idle dependency-tail time; active I/O keeps its own budget.
    #[arg(long)]
    case_no_progress_timeout_ms: Option<u64>,
    #[arg(long)]
    lazy_case_dependencies: bool,
    #[arg(long)]
    dependency_cache_bytes: Option<usize>,
    #[arg(long)]
    case_prepare_timeout_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ReplayFile {
    replay: ReplayFileValues,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ReplayFileValues {
    pre_match: Option<bool>,
    stream_timing: Option<traffic_e2e::ReplayStreamTiming>,
    stream_interval_cap_ms: Option<u64>,
    case_no_progress_timeout_ms: Option<u64>,
    case: Option<PathBuf>,
    dns_listen: Option<SocketAddr>,
    tcp_listen: Option<SocketAddr>,
    fake_cidr: Option<String>,
    report: Option<PathBuf>,
    session: Option<PathBuf>,
    control_socket: Option<PathBuf>,
    enable_intercept: Option<bool>,
    policy: Option<PathBuf>,
    owner_uid: Option<serde_yaml::Value>,
    user: Option<serde_yaml::Value>,
    record_user: Option<serde_yaml::Value>,
    all_users: Option<serde_yaml::Value>,
    case_dependency_post_response_window_ms: Option<u64>,
    dependency_loading: Option<traffic_e2e::ReplayDependencyLoading>,
}

struct ResolvedReplay {
    session_events: bool,
    pre_match: bool,
    stream_timing: Option<traffic_e2e::ReplayStreamTiming>,
    stream_interval_cap_ms: u64,
    case_no_progress_timeout_ms: u64,
    request_timeout_ms: u64,
    dependency_loading: traffic_e2e::ReplayDependencyLoading,
    case: PathBuf,
    case_ids: Vec<String>,
    report: PathBuf,
    session: PathBuf,
    control_socket: PathBuf,
    timers: Option<ReplayTimerConfig>,
    dns_listen: SocketAddr,
    tcp_listen: SocketAddr,
    udp_port: u16,
    fake_cidr: String,
    intercept: bool,
    policy: Option<PathBuf>,
    recorder_config: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    ca_key: Option<PathBuf>,
    http_ignore_query_params: Vec<String>,
    case_dependency_post_response_window_ms: u64,
}

pub(super) async fn run(args: ReplayArgs) -> Result<()> {
    let resolved = resolve(args)?;
    let (allowed_unused_http, process_owned_dependencies) = if resolved.session_events {
        (Default::default(), Default::default())
    } else {
        (
            load_allowed_unused_http(resolved.recorder_config.clone())?,
            load_background_dependencies(resolved.recorder_config.as_deref())?,
        )
    };
    let mut interception = if resolved.intercept {
        Some(Guard::enable_replay(
            DnsConfig {
                dns_ip: resolved.dns_listen.ip().to_string(),
                dns_port: resolved.dns_listen.port(),
            },
            FakeIpConfig {
                fake_cidr: resolved.fake_cidr.clone(),
                tcp_port: resolved.tcp_listen.port(),
                udp_port: resolved.udp_port,
                tcp: true,
                udp: false,
            },
        )?)
    } else {
        None
    };
    let lifecycle = ReplayLifecycleConfig {
        pre_match: resolved.pre_match,
        stream_timing: resolved.stream_timing,
        stream_interval_cap_ms: resolved.stream_interval_cap_ms,
        case_no_progress_timeout: std::time::Duration::from_millis(
            resolved.case_no_progress_timeout_ms,
        ),
        request_timeout: std::time::Duration::from_millis(resolved.request_timeout_ms),
        dependency_loading: resolved.dependency_loading,
        case_dependency_post_response_window: std::time::Duration::from_millis(
            resolved.case_dependency_post_response_window_ms,
        ),
    };
    let config = ReplayConfig {
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
        process_owned_dependencies,
        allowed_unused_http,
    };
    let counters = resolved
        .intercept
        .then(super::interception::counter_reader)
        .transpose()?;
    let replay = async {
        if resolved.session_events {
            run_session_replay(config, lifecycle, counters, resolved.timers).await
        } else {
            run_replay_with_timer_config(config, lifecycle, counters, resolved.timers).await
        }
    };
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
            let file: ReplayFile = serde_yaml::from_str(&source)
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
    let recorder_config = args
        .recorder_config
        .as_deref()
        .map(|path| absolute_from(&cwd, path));
    if let Some(path) = recorder_config.as_deref() {
        ensure!(
            path.is_file(),
            "recorder config not found: {}",
            path.display()
        );
    }
    let recorder_defaults = recorder_config
        .as_deref()
        .map(AppConfig::load)
        .transpose()?;
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
    let case_ids = if args.apis.is_empty() {
        args.case_ids
    } else {
        resolve_recording_api_case_ids(&case, &args.apis)?
    };
    let dns_listen = args
        .dns_listen
        .or(file.replay.dns_listen)
        .or_else(|| {
            recorder_defaults
                .as_ref()
                .map(|config| config.dns_mock.listen)
        })
        .unwrap_or(DEFAULT_DNS_MOCK_LISTEN.parse()?);
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
        .or_else(|| {
            recorder_defaults
                .as_ref()
                .map(|config| config.tcp_gateway.listen)
        })
        .unwrap_or(DEFAULT_TCP_GATEWAY_LISTEN.parse()?);
    let udp_port = recorder_defaults
        .as_ref()
        .map_or(DEFAULT_UDP_GATEWAY_PORT, |config| {
            config.udp_gateway.listen.port()
        });
    let fake_cidr = args
        .fake_cidr
        .or(file.replay.fake_cidr)
        .or_else(|| {
            recorder_defaults
                .as_ref()
                .map(|config| config.dns_mock.fake_cidr.clone())
        })
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
    let case_dependency_post_response_window_ms = args
        .case_dependency_post_response_window_ms
        .or(file.replay.case_dependency_post_response_window_ms)
        .unwrap_or(traffic_e2e::DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS);
    let mut dependency_loading = file.replay.dependency_loading.unwrap_or_default();
    dependency_loading.lazy_cases |= args.lazy_case_dependencies;
    if let Some(bytes) = args.dependency_cache_bytes {
        dependency_loading.cache_bytes = bytes;
    }
    if let Some(seconds) = args.case_prepare_timeout_seconds {
        dependency_loading.case_timeout_seconds = seconds;
    }
    let case_no_progress_timeout_ms = args
        .case_no_progress_timeout_ms
        .or(file.replay.case_no_progress_timeout_ms)
        .unwrap_or(traffic_e2e::DEFAULT_REPLAY_CASE_NO_PROGRESS_TIMEOUT_MS);
    ensure!(
        case_no_progress_timeout_ms > 0,
        "case_no_progress_timeout_ms must be positive"
    );
    let pre_match = args.pre_match || file.replay.pre_match.unwrap_or(false);
    ensure!(
        !args.session_events || !pre_match,
        "session Replay requires strict matching"
    );
    Ok(ResolvedReplay {
        session_events: args.session_events,
        pre_match,
        stream_timing: args.stream_timing.or(file.replay.stream_timing),
        stream_interval_cap_ms: args
            .stream_interval_cap_ms
            .or(file.replay.stream_interval_cap_ms)
            .unwrap_or(traffic_e2e::DEFAULT_REPLAY_STREAM_INTERVAL_CAP_MS),
        case_no_progress_timeout_ms,
        request_timeout_ms: recorder_defaults.as_ref().map_or_else(
            || AppConfig::default().http_gateway.request_timeout_ms,
            |config| config.http_gateway.request_timeout_ms,
        ),
        dependency_loading,
        case,
        case_ids,
        report,
        session,
        control_socket,
        timers: args
            .timer_plan
            .zip(args.timer_socket)
            .map(|(plan, socket)| ReplayTimerConfig {
                plan_path: absolute_from(&cwd, &plan),
                socket_path: absolute_from(&cwd, &socket),
            }),
        dns_listen,
        tcp_listen,
        udp_port,
        fake_cidr,
        intercept,
        policy,
        recorder_config,
        ca_cert: args.ca_cert.map(|path| absolute_from(&cwd, &path)),
        ca_key: args.ca_key.map(|path| absolute_from(&cwd, &path)),
        http_ignore_query_params: args.http_ignore_query_params,
        case_dependency_post_response_window_ms,
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
) -> Result<Option<ReplayAllowedUnusedHttpConfig>> {
    let Some(config_path) = recorder_config else {
        return Ok(None);
    };
    let config_path = config_path.canonicalize()?;
    let config = AppConfig::load(&config_path)?;
    Ok(Some(ReplayAllowedUnusedHttpConfig {
        config_path,
        hosts: config
            .http_gateway
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
        .map(|path| AppConfig::load(path).map(|config| config.process_owned_dependencies))
        .transpose()
        .map(Option::unwrap_or_default)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
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
        let file: ReplayFile = serde_yaml::from_str("replay:\n  owner_uid: 1000\n").unwrap();
        let error = reject_file_owner(&file.replay).unwrap_err().to_string();
        assert!(error.contains("owner_uid"));
        assert!(error.contains("fixed user"));
    }

    #[test]
    fn replay_file_rejects_unknown_fields() {
        assert!(serde_yaml::from_str::<ReplayFile>("replay:\n  unknown: true\n").is_err());
    }

    #[test]
    fn rejects_removed_upstream_dns_setting() {
        assert!(
            TestCli::try_parse_from(["test", "--upstream-dns", "10.10.10.10:53", "cases"]).is_err()
        );
        assert!(
            serde_yaml::from_str::<ReplayFile>("replay:\n  upstream_dns: 10.10.10.10:53\n")
                .is_err()
        );
    }

    #[test]
    fn replay_file_paths_are_relative_to_the_config() {
        let directory = tempfile::tempdir().unwrap();
        let config_dir = directory.path().join("config");
        let case_dir = directory.path().join("cases");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&case_dir).unwrap();
        let config = config_dir.join("replay.yaml");
        std::fs::write(
            &config,
            "replay:\n  case: ../cases\n  enable_intercept: false\n",
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
    fn general_stream_timing_is_optional_and_cli_overrides_replay_file() {
        use traffic_e2e::ReplayStreamTiming::{Fast, Recorded};
        let directory = tempfile::tempdir().unwrap();
        let case = Some(directory.path().to_path_buf());
        let resolved = resolve(replay_args(case.clone(), None)).unwrap();
        assert_eq!(resolved.stream_timing, None);
        let config = directory.path().join("replay.yaml");
        std::fs::write(
            &config,
            "replay:\n  stream_timing: fast\n  stream_interval_cap_ms: 10\n",
        )
        .unwrap();
        let from_file = resolve(replay_args(case.clone(), Some(config.clone()))).unwrap();
        assert_eq!(from_file.stream_timing, Some(Fast));
        assert_eq!(from_file.stream_interval_cap_ms, 10);
        let mut args = replay_args(case, Some(config));
        args.stream_timing = Some(Recorded);
        args.stream_interval_cap_ms = Some(0);
        let from_cli = resolve(args).unwrap();
        assert_eq!(from_cli.stream_timing, Some(Recorded));
        assert_eq!(from_cli.stream_interval_cap_ms, 0);
        assert!(TestCli::try_parse_from(["test", "--stream-timing", "fast", "cases"]).is_ok());
        assert!(
            TestCli::try_parse_from(["test", "--http-stream-timing", "fast", "cases"]).is_err()
        );
        assert!(
            serde_yaml::from_str::<ReplayFile>("replay:\n  http_stream_timing: fast\n").is_err()
        );
    }

    #[test]
    fn replay_idle_budget_defaults_and_cli_override_remain_independent_of_loading() {
        let directory = tempfile::tempdir().unwrap();
        let case = directory.path().join("cases");
        std::fs::create_dir_all(&case).unwrap();
        let resolved = resolve(replay_args(Some(case.clone()), None)).unwrap();
        assert_eq!(resolved.case_no_progress_timeout_ms, 2000);
        let config = directory.path().join("replay.yaml");
        std::fs::write(&config, "replay:\n  case_no_progress_timeout_ms: 12000\n").unwrap();
        assert_eq!(
            resolve(replay_args(Some(case.clone()), Some(config.clone())))
                .unwrap()
                .case_no_progress_timeout_ms,
            12000
        );
        let mut args = replay_args(Some(case.clone()), Some(config));
        args.case_prepare_timeout_seconds = Some(180);
        args.case_no_progress_timeout_ms = Some(750);
        let resolved = resolve(args).unwrap();
        assert_eq!(resolved.case_no_progress_timeout_ms, 750);
        assert_eq!(resolved.dependency_loading.case_timeout_seconds, 180);
        let mut args = replay_args(Some(case), None);
        args.case_no_progress_timeout_ms = Some(0);
        assert!(
            resolve(args)
                .err()
                .unwrap()
                .to_string()
                .contains("must be positive")
        );
    }

    #[tokio::test]
    async fn api_selection_resolves_cases_across_recording_members() {
        let directory = tempfile::tempdir().unwrap();
        let recordings = directory.path().join("recordings");
        let recorder = traffic_e2e::Recorder::new(&recordings).await.unwrap();
        for (id, member, uri) in [
            (1, "widgets-alpha", "/api/widgets/alpha"),
            (2, "widgets-beta", "/api/widgets/beta"),
            (3, "other", "/api/other"),
        ] {
            let case = traffic_e2e::CaseContext {
                id: uuid::Uuid::from_u128(id),
                rule_name: member.into(),
                uri_group: None,
            };
            recorder
                .write_case_json(
                    &case,
                    "admission.json",
                    &serde_json::json!({"fixture":true}),
                )
                .await
                .unwrap();
            recorder
                .write_case_json(
                    &case,
                    "request.json",
                    &serde_json::json!({"method":"GET","uri":uri,"api_pattern":uri}),
                )
                .await
                .unwrap();
            recorder
                .write_case_json(&case, "expected-response.json", &serde_json::json!({}))
                .await
                .unwrap();
            recorder.publish_case(&case).await.unwrap();
        }
        let has_failed_cases = recorder.finish_run().await.unwrap();
        assert!(
            !has_failed_cases,
            "the fixture must publish every Case successfully"
        );
        let mut runs = std::fs::read_dir(&recordings)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(runs.len(), 1);
        let run = runs.remove(0);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(run.join("dependency-manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["schema"], "traffic-recording/v13");
        assert_eq!(manifest["sealed"], true);
        assert_eq!(manifest["capture_complete"], true);
        let inputs = manifest["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 3);
        assert!(inputs.iter().all(|input| input["complete"] == true));
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(run.join("recording-run.json")).unwrap())
                .unwrap();
        assert_eq!(report["status"], "completed");
        assert_eq!(report["published_cases"], 3);
        assert_eq!(report["failed_cases"], 0);
        let mut args = replay_args(Some(run), None);
        args.apis = vec!["GET /api/widgets/*".parse().unwrap()];

        let resolved = resolve(args).unwrap();

        assert_eq!(
            resolved.case_ids,
            [
                uuid::Uuid::from_u128(1).to_string(),
                uuid::Uuid::from_u128(2).to_string()
            ]
        );
    }

    #[test]
    fn api_and_case_id_selectors_are_mutually_exclusive() {
        let error = TestCli::try_parse_from([
            "test",
            "--api",
            "GET /api/widgets/*",
            "--case-id",
            "case-a",
            "cases",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn no_intercept_accepts_an_ipv6_dns_listener() {
        let directory = tempfile::tempdir().unwrap();
        let mut args = replay_args(Some(directory.path().to_path_buf()), None);
        args.no_intercept = true;
        args.dns_listen = Some("[::1]:15353".parse().unwrap());

        assert!(resolve(args).is_ok());
    }

    #[test]
    fn replay_uses_low_ports_without_explicit_configuration() {
        let directory = tempfile::tempdir().unwrap();

        let resolved = resolve(replay_args(Some(directory.path().to_path_buf()), None)).unwrap();

        assert_eq!(resolved.dns_listen.port(), 4_053);
        assert_eq!(resolved.tcp_listen.port(), 4_001);
        assert_eq!(resolved.udp_port, 4_002);
        assert_eq!(
            resolved.case_dependency_post_response_window_ms,
            traffic_e2e::DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS
        );
    }

    #[test]
    fn command_line_post_response_window_overrides_replay_file() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("replay.yaml");
        std::fs::write(
            &config,
            "replay:\n  case: .\n  case_dependency_post_response_window_ms: 25\n",
        )
        .unwrap();
        let mut args = replay_args(None, Some(config));
        args.case_dependency_post_response_window_ms = Some(5);

        let resolved = resolve(args).unwrap();

        assert_eq!(resolved.case_dependency_post_response_window_ms, 5);
    }

    #[test]
    fn recorder_ports_remain_replay_defaults_when_explicit() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join(".traffic-e2e")).unwrap();
        let recorder_config = directory.path().join(".traffic-e2e/project.yaml");
        std::fs::write(
            &recorder_config,
            "version: 18\nproject:\n  policy: .traffic-e2e/policy.yaml\nrecorder:\n  dns_mock:\n    listen: 127.0.0.153:15353\n  tcp_gateway:\n    listen: 127.0.0.1:15001\n  udp_gateway:\n    listen: 127.0.0.1:15002\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join(".traffic-e2e/policy.yaml"),
            "format: traffic-policy/v3\nrules: []\n",
        )
        .unwrap();
        let mut args = replay_args(Some(directory.path().to_path_buf()), None);
        args.recorder_config = Some(recorder_config);

        let resolved = resolve(args).unwrap();

        assert_eq!(resolved.dns_listen.port(), 15_353);
        assert_eq!(resolved.tcp_listen.port(), 15_001);
        assert_eq!(resolved.udp_port, 15_002);
    }

    fn replay_args(case: Option<PathBuf>, config: Option<PathBuf>) -> ReplayArgs {
        ReplayArgs {
            session_events: false,
            pre_match: false,
            stream_timing: None,
            stream_interval_cap_ms: None,
            case_no_progress_timeout_ms: None,
            case,
            config,
            intercept: false,
            no_intercept: false,
            apis: Vec::new(),
            case_ids: Vec::new(),
            report: None,
            session: None,
            control_socket: None,
            timer_plan: None,
            timer_socket: None,
            dns_listen: None,
            tcp_listen: None,
            fake_cidr: None,
            policy: None,
            recorder_config: None,
            ca_cert: None,
            ca_key: None,
            http_ignore_query_params: Vec::new(),
            case_dependency_post_response_window_ms: None,
            lazy_case_dependencies: false,
            dependency_cache_bytes: None,
            case_prepare_timeout_seconds: None,
        }
    }
}
