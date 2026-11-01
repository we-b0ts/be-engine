use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::model::{
    DEFAULT_TARGET_STARTUP_TIMEOUT_SECONDS, DeliveryProjectConfig, ProjectConfig, ProjectSettings,
    ReplayProjectConfig, ResolvedProjectConfig, RunLayout, SourceProjectConfig, StateProjectConfig,
    TargetProjectConfig, VerificationProjectConfig,
};
use super::project_validation::validate_project_config;
use super::{E2eRunInitOptions, E2eRunInitResult, branch};
use crate::replay::validate_replay_policy;
use anyhow::{Context, Result, bail, ensure};

mod cache;

pub(super) const CONFIG_VERSION: u32 = 18;
pub(super) const DEFAULT_RUNTIME_ROOT: &str = crate::internal_runtime::PROJECT_RELATIVE_ROOT;
pub(crate) const PROJECT_CONFIG_FILE: &str = "project.yaml";

pub(super) fn initialize(options: E2eRunInitOptions) -> Result<E2eRunInitResult> {
    let target_root = fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    branch::validate_pr_base(&target_root, &options.pr_base)?;

    let traffic_e2e_dir = target_root.join(crate::repository::TRAFFIC_E2E_ROOT);
    let config_path = traffic_e2e_dir.join(PROJECT_CONFIG_FILE);
    let existing = match fs::symlink_metadata(&config_path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", config_path.display()));
        }
    };
    let replaced = existing.is_some();
    if let Some(metadata) = existing {
        ensure!(
            options.force,
            "{} already exists; refusing to replace it",
            config_path.display()
        );
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "{} must be a regular file and not a symlink",
            config_path.display()
        );
    }

    let replay_policy = resolve_under(&target_root, &options.replay_policy);
    ensure!(
        replay_policy.is_file(),
        "replay policy does not exist: {}",
        replay_policy.display()
    );
    let replay = validate_replay_policy(&replay_policy).context("invalid replay policy")?;
    ensure!(
        replay.runner_owned_response_assertions,
        "managed project replay requires verification policy version 3 with runner-owned response assertions"
    );
    let recorder_config = resolve_under(&target_root, &options.recorder_config);
    ensure!(
        recorder_config.is_file(),
        "recorder config does not exist: {}",
        recorder_config.display()
    );
    let recorder = crate::config::AppConfig::load_static(&recorder_config)?;
    ensure!(
        !recorder.http_gateway.enabled || recorder.http_gateway.ready.enabled,
        "managed project replay with http_gateway.enabled requires an enabled http_gateway.ready probe"
    );
    let runtime_root_setting = PathBuf::from(DEFAULT_RUNTIME_ROOT);
    let runtime_root = traffic_e2e_dir.join(&runtime_root_setting);
    require_internal_root_ignored(&target_root, &runtime_root)?;

    let payload = render_project_config(&options, recorder)?;
    if options.force {
        crate::config::edit::write_atomic(&config_path, &payload)?;
    } else {
        crate::config::edit::create_many_atomic(&[(config_path.clone(), payload)])?;
    }
    let persisted = load_project_config(&target_root, &config_path)?;
    crate::config::regression::initialize(&target_root)?;

    Ok(E2eRunInitResult {
        config: config_path,
        runtime_root,
        pr_base: persisted.project.delivery.pr_base,
        recorder_feedback: true,
        replaced,
    })
}

pub(crate) fn render_project_config(
    options: &E2eRunInitOptions,
    recorder: crate::config::AppConfig,
) -> Result<Vec<u8>> {
    let project_config = ProjectConfig {
        version: CONFIG_VERSION,
        project: ProjectSettings {
            policy: options.replay_policy.clone(),
            source: SourceProjectConfig {
                snapshot: PathBuf::from(crate::repository::LOCAL_SOURCE_ROOT),
            },
            target: TargetProjectConfig {
                dockerfile: options.target_dockerfile.clone(),
                startup_timeout_seconds: DEFAULT_TARGET_STARTUP_TIMEOUT_SECONDS,
                startup: crate::startup::normalized_config(options.target_startup.clone())?,
                runtime_outputs: Vec::new(),
            },
            replay: ReplayProjectConfig {
                pre_match: true,
                http_stream_timing: Default::default(),
                socketio_timing: Default::default(),
                case_no_progress_timeout_ms:
                    crate::replay::DEFAULT_REPLAY_CASE_NO_PROGRESS_TIMEOUT_MS,
                startup_timeout_seconds: super::model::DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS,
                request_timeout_allowance_seconds:
                    super::model::DEFAULT_TARGET_REQUEST_TIMEOUT_SECONDS,
                dependency_loading: crate::replay::ReplayDependencyLoading::managed_default(),
                case_dependency_post_response_window_ms:
                    crate::replay::DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS,
            },
            verification: VerificationProjectConfig::default(),
            delivery: DeliveryProjectConfig {
                pr_base: options.pr_base.clone(),
                quality_check: super::model::default_quality_check(),
                managed_paths: Vec::new(),
            },
            state: StateProjectConfig {
                runtime_root: PathBuf::from(DEFAULT_RUNTIME_ROOT),
            },
        },
        recorder,
    };
    validate_project_config(&project_config)?;
    let mut payload = serde_yaml::to_string(&project_config)?.into_bytes();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }
    Ok(payload)
}

pub(super) fn resolve_layout(
    target_root: &Path,
    case_source: &Path,
    explicit_run_key: Option<&str>,
) -> Result<(ResolvedProjectConfig, RunLayout)> {
    let (target_root, resolved) = resolve_project(target_root)?;
    require_regular_file(&resolved.target_dockerfile, "target Dockerfile")?;
    ensure!(
        resolved.recorder_config.is_file(),
        "recorder config does not exist: {}",
        resolved.recorder_config.display()
    );
    let traffic_e2e_dir = target_root.join(crate::repository::TRAFFIC_E2E_ROOT);
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let config_path = traffic_e2e_dir.join(PROJECT_CONFIG_FILE);
    let config = load_project_config(&target_root, &config_path)?;
    let internal_root = resolve_under(&traffic_e2e_dir, &config.project.state.runtime_root);
    ensure!(
        internal_root.starts_with(&traffic_e2e_dir) && internal_root != traffic_e2e_dir,
        "state.runtime_root must be a child of .traffic-e2e"
    );
    let run_key = match explicit_run_key {
        Some(value) => validate_run_key(value)?,
        None => derive_run_key(&case_source)?,
    };
    let run_root = internal_root.join(&run_key);
    let layout = RunLayout {
        target_root,
        run_key,
        case_source,
        progress_path: traffic_e2e_dir.join("progress.yaml"),
        legacy_progress_path: traffic_e2e_dir.join("e2e-progress.yaml"),
        internal_root: internal_root.clone(),
        current_path: internal_root.join("current.yaml"),
        index_path: run_root.join("state.yaml"),
        group_index_path: run_root.join("case-groups.json"),
        active_dir: run_root.join(".active"),
        latest_dir: run_root.join("latest"),
        run_root,
    };
    Ok((resolved, layout))
}

pub(crate) fn resolve_project(target_root: &Path) -> Result<(PathBuf, ResolvedProjectConfig)> {
    let target_root = fs::canonicalize(target_root)
        .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
    if let Some(project) = cache::get(&target_root) {
        return Ok((target_root, project));
    }
    let config_path = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(PROJECT_CONFIG_FILE);
    let config = load_project_config(&target_root, &config_path)?;
    let managed = super::delivery::resolve_project_managed_paths(
        &target_root,
        &config.project.delivery.managed_paths,
    )?;
    let policy_path = crate::config::resolve_unified_policy_path(&config_path)?;
    let policy = validate_replay_policy(&policy_path).context("invalid replay policy")?;
    ensure!(
        policy.runner_owned_response_assertions,
        "managed project replay requires verification policy version 3 with runner-owned response assertions"
    );
    let recorder_config = config_path.clone();
    let source_traffic_policy = policy_path.clone();
    let recorder = crate::config::AppConfig::load(&recorder_config)?;
    ensure!(
        !recorder.http_gateway.enabled || recorder.http_gateway.ready.enabled,
        "managed project replay with http_gateway.enabled requires an enabled http_gateway.ready probe"
    );
    let target_request_timeout =
        Duration::from_secs(config.project.replay.request_timeout_allowance_seconds);
    let target_max_response_bytes = recorder.recording.max_body_bytes;
    let target_port = recorder_target_http_port(&recorder.http_gateway.matched_upstream)?;
    let target_http_readiness_enabled = recorder.http_gateway.enabled;
    let target_motan_connect_timeout =
        Duration::from_millis(recorder.motan_gateway.connect_timeout_ms);
    let target_motan_request_timeout =
        Duration::from_millis(recorder.motan_gateway.request_timeout_ms);
    let target_motan_limits = motan_protocol::Limits {
        max_frame_bytes: recorder.motan_gateway.max_frame_bytes,
        max_metadata_bytes: recorder.motan_gateway.max_frame_bytes,
        max_body_bytes: recorder.motan_gateway.max_frame_bytes,
    };
    let target_motan_upstream = recorder
        .motan_gateway
        .enabled
        .then(|| {
            let port = crate::platform::endpoint_port(
                &recorder.motan_gateway.matched_upstream,
                "motan_gateway.matched_upstream",
            )?;
            Ok::<String, anyhow::Error>(format!("127.0.0.1:{port}"))
        })
        .transpose()?;
    let project = ResolvedProjectConfig {
        replay_pre_match: config.project.replay.pre_match,
        replay_http_stream_timing: config.project.replay.http_stream_timing,
        replay_socketio_timing: config.project.replay.socketio_timing,
        replay_case_no_progress_timeout: Duration::from_millis(
            config.project.replay.case_no_progress_timeout_ms,
        ),
        replay_loading: config.project.replay.dependency_loading,
        target_dockerfile: resolve_under(&target_root, &config.project.target.dockerfile),
        target_build_contexts: managed.build_contexts,
        target_startup: config.project.target.startup,
        target_runtime_outputs: config.project.target.runtime_outputs,
        target_http_origin: format!("http://127.0.0.1:{target_port}"),
        target_port,
        target_http_readiness_enabled,
        target_motan_upstream,
        target_motan_connect_timeout,
        target_motan_request_timeout,
        target_motan_limits,
        target_readiness_path: recorder.http_gateway.ready.path,
        target_readiness_status: recorder.http_gateway.ready.success_status,
        target_startup_timeout: Duration::from_secs(config.project.target.startup_timeout_seconds),
        target_request_timeout,
        target_max_response_bytes,
        replay_policy: policy_path,
        replay_case_dependency_post_response_window: Duration::from_millis(
            config
                .project
                .replay
                .case_dependency_post_response_window_ms,
        ),
        max_failed_cases_per_api: config.project.verification.max_failed_cases_per_api,
        replay_startup_timeout: Duration::from_secs(config.project.replay.startup_timeout_seconds),
        pr_base: config.project.delivery.pr_base,
        quality_check: config.project.delivery.quality_check,
        managed_paths: managed.paths,
        recorder_config,
        source_traffic_policy,
        runner_owned_response_assertions: policy.runner_owned_response_assertions,
    };
    cache::insert(target_root.clone(), project.clone());
    Ok((target_root, project))
}

pub(crate) fn with_project_resolution_cache<T>(operation: impl FnOnce() -> T) -> T {
    cache::scope(operation)
}

pub(super) fn require_internal_root_ignored(
    target_root: &Path,
    internal_root: &Path,
) -> Result<()> {
    fs::create_dir_all(internal_root)?;
    let probe = internal_root.join(".ignore-check");
    let relative = probe
        .strip_prefix(target_root)
        .context("traffic E2E internal root is outside target repository")?;
    let output = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .arg("check-ignore")
        .arg("-q")
        .arg(relative)
        .status()
        .context("failed to run git check-ignore")?;
    ensure!(
        output.success(),
        "{} must be ignored by the target repository before running traffic E2E",
        internal_root.display()
    );
    Ok(())
}

pub(super) fn load_project_config(target_root: &Path, config_path: &Path) -> Result<ProjectConfig> {
    if let Some(config) = cache::document(config_path) {
        return Ok(config);
    }
    if !config_path.exists() {
        bail!(
            "{} is missing; from the target repository run `backend-rewrite init \
             --source-pod <pod> --namespace <namespace>`",
            config_path.display()
        );
    }
    let config: ProjectConfig = super::store::read_yaml(config_path).with_context(|| {
        format!(
            "{} is incomplete or obsolete; in-place migration is not implemented, so preserve \
             the existing configuration and initialize a clean target repository",
            config_path.display()
        )
    })?;
    validate_project_config(&config).with_context(|| {
        format!(
            "{} is incomplete or obsolete; in-place migration is not implemented, so preserve \
             the existing configuration and initialize a clean target repository",
            config_path.display()
        )
    })?;
    branch::validate_pr_base(target_root, &config.project.delivery.pr_base)?;
    cache::insert_document(config_path.to_path_buf(), config.clone());
    Ok(config)
}

fn recorder_target_http_port(matched_upstream: &str) -> Result<u16> {
    let origin = url::Url::parse(matched_upstream)
        .context("http_gateway.matched_upstream must be a valid HTTP origin")?;
    ensure!(
        matches!(origin.scheme(), "http" | "https"),
        "http_gateway.matched_upstream must use HTTP or HTTPS"
    );
    ensure!(
        origin.host_str().is_some(),
        "http_gateway.matched_upstream must contain a host"
    );
    origin
        .port_or_known_default()
        .context("http_gateway.matched_upstream must contain a known port")
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink: {}",
        path.display()
    );
    Ok(())
}

fn resolve_under(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn derive_run_key(case_source: &Path) -> Result<String> {
    let name = case_source
        .file_name()
        .and_then(|value| value.to_str())
        .context("case source has no UTF-8 directory name")?;
    let parent = case_source
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str());
    let candidate = match parent {
        Some(parent)
            if parent.len() == 14 && parent.chars().all(|value| value.is_ascii_digit()) =>
        {
            format!("{parent}-{name}")
        }
        _ => name.to_string(),
    };
    validate_run_key(&candidate)
}

fn validate_run_key(value: &str) -> Result<String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        bail!("run key must contain only ASCII letters, digits, '.', '_', or '-'");
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;

    use tempfile::TempDir;

    use super::*;
    mod capture_tests;
    mod socketio_timing_tests;
    use crate::e2e_run::model::MAX_TARGET_STARTUP_TIMEOUT_SECONDS;

    #[test]
    fn replay_idle_budget_defaults_to_two_seconds_and_preserves_explicit_overrides() {
        let absent: ReplayProjectConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(absent.case_no_progress_timeout_ms, 2000);
        assert_eq!(
            crate::replay::ReplayLifecycleConfig::default()
                .case_no_progress_timeout
                .as_millis(),
            2000
        );
        let explicit: ReplayProjectConfig =
            serde_json::from_value(serde_json::json!({"case_no_progress_timeout_ms":5000}))
                .unwrap();
        assert_eq!(explicit.case_no_progress_timeout_ms, 5000);
    }

    #[test]
    fn older_project_replay_settings_preserve_recorded_timing_until_fast_is_requested() {
        let absent: ReplayProjectConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(absent.pre_match);
        assert_eq!(
            absent.http_stream_timing,
            crate::replay::ReplayHttpStreamTiming::Recorded
        );
        let explicit: ReplayProjectConfig =
            serde_json::from_value(serde_json::json!({"http_stream_timing":"fast"})).unwrap();
        assert_eq!(
            explicit.http_stream_timing,
            crate::replay::ReplayHttpStreamTiming::Fast
        );
    }

    fn write_input_project(root: &Path, recorder: &crate::config::AppConfig) {
        let recorder = serde_yaml::to_string(recorder).unwrap();
        let recorder = recorder
            .lines()
            .map(|line| format!("  {line}\n"))
            .collect::<String>();
        fs::write(
            root.join("config/project.yaml"),
            format!("version: 18\nproject:\n  policy: config/replay.yaml\nrecorder:\n{recorder}"),
        )
        .unwrap();
    }

    fn target() -> TempDir {
        let target = tempfile::tempdir().unwrap();
        let root = target.path();
        assert!(
            Command::new("git")
                .args(["init", "-q", "-b", "integration"])
                .arg(root)
                .status()
                .unwrap()
                .success()
        );
        fs::write(root.join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
        fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
        fs::write(
            root.join(".traffic-e2e/Dockerfile.target"),
            "FROM scratch\nUSER 998:998\nENTRYPOINT [\"/target\"]\n",
        )
        .unwrap();
        fs::write(
            root.join(".dockerignore"),
            ".git/\n.traffic-e2e/local/\ntarget/\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("config")).unwrap();
        fs::write(
            root.join("config/replay.yaml"),
            "format: traffic-policy/v3\nrules: []\n",
        )
        .unwrap();
        let mut recorder = crate::config::AppConfig::default();
        recorder.http_gateway.ready.enabled = true;
        recorder.http_gateway.ready.path = "/healthz".to_string();
        recorder.http_gateway.ready.success_status = 404;
        recorder.http_gateway.rules = vec![crate::config::HttpGatewayRuleConfig {
            name: Some("http-rule".to_string()),
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/".to_string()],
            ..Default::default()
        }];
        write_input_project(root, &recorder);
        fs::write(
            root.join("config/replay.yaml"),
            "format: traffic-policy/v3\nrules: []\n",
        )
        .unwrap();
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["add", "."])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args([
                    "-c",
                    "user.name=E2E Test",
                    "-c",
                    "user.email=e2e-test@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "initial",
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["switch", "-q", "-c", "feature"])
                .status()
                .unwrap()
                .success()
        );
        target
    }

    #[test]
    fn retired_breeze_startup_configuration_is_rejected() {
        let target = target();
        let rendered =
            render_project_config(&options(target.path()), crate::config::AppConfig::default())
                .unwrap();
        let mut value: serde_yaml::Value = serde_yaml::from_slice(&rendered).unwrap();
        value["project"]["breeze"] = serde_yaml::from_str("container: breeze").unwrap();
        let error = serde_yaml::from_value::<ProjectConfig>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field `breeze`"));
    }

    fn options(target_root: &Path) -> E2eRunInitOptions {
        E2eRunInitOptions {
            target_root: target_root.to_path_buf(),
            target_dockerfile: PathBuf::from(".traffic-e2e/Dockerfile.target"),
            target_startup: crate::startup::StartupConfig::default(),
            replay_policy: PathBuf::from("config/replay.yaml"),
            pr_base: "integration".to_string(),
            recorder_config: PathBuf::from("config/project.yaml"),
            force: false,
        }
    }

    #[test]
    fn initialize_generates_valid_project_config() {
        let target = target();
        let result = initialize(options(target.path())).unwrap();

        assert!(!result.replaced);
        assert!(result.recorder_feedback);
        assert_eq!(
            result.config,
            target.path().join(".traffic-e2e/project.yaml")
        );
        assert!(!target.path().join(".traffic-e2e/e2e.yaml").exists());
        let config: ProjectConfig =
            serde_yaml::from_str(&fs::read_to_string(&result.config).unwrap()).unwrap();
        assert_eq!(config.version, CONFIG_VERSION);
        assert_eq!(
            config.project.source.snapshot,
            PathBuf::from(crate::repository::LOCAL_SOURCE_ROOT)
        );
        assert_eq!(
            config.project.target.dockerfile,
            PathBuf::from(".traffic-e2e/Dockerfile.target")
        );
        assert_eq!(
            config.project.target.startup_timeout_seconds,
            DEFAULT_TARGET_STARTUP_TIMEOUT_SECONDS
        );
        assert_eq!(config.project.policy, PathBuf::from("config/replay.yaml"));
        assert_eq!(
            config
                .project
                .replay
                .case_dependency_post_response_window_ms,
            crate::replay::DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS
        );
        assert_eq!(
            config.project.verification.max_failed_cases_per_api,
            super::super::model::DEFAULT_MAX_FAILED_CASES_PER_API
        );
        let raw = fs::read_to_string(&result.config).unwrap();
        assert!(raw.contains("max_failed_cases_per_api: 10"));
        for duplicate in [
            "readiness_path",
            "readiness_status",
            "request_timeout_seconds",
            "http_host",
            "motan_port",
        ] {
            assert!(
                !raw.contains(duplicate),
                "found duplicate field {duplicate}"
            );
        }
        assert!(!raw.lines().any(|line| line.trim_start() == "port: 8081"));
        assert_eq!(config.project.delivery.pr_base, "integration");
        assert!(config.project.delivery.managed_paths.is_empty());
        assert_eq!(result.pr_base, "integration");
        assert_eq!(
            config.project.state.runtime_root,
            PathBuf::from(DEFAULT_RUNTIME_ROOT)
        );
    }

    #[test]
    fn managed_replay_uses_the_project_target_startup_timeout() {
        let target = target();
        initialize(options(target.path())).unwrap();
        let config_path = target.path().join(".traffic-e2e/project.yaml");
        let mut project: ProjectConfig =
            serde_yaml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        project.project.target.startup_timeout_seconds = 240;
        project.project.replay.startup_timeout_seconds = 300;
        project.project.replay.request_timeout_allowance_seconds = 120;
        fs::write(config_path, serde_yaml::to_string(&project).unwrap()).unwrap();

        let (_, config) = resolve_project(target.path()).unwrap();

        assert_eq!(config.target_startup_timeout, Duration::from_secs(240));
        assert_eq!(config.replay_startup_timeout, Duration::from_secs(300));
        assert_eq!(config.target_request_timeout, Duration::from_secs(120));
        let case = tempfile::tempdir().unwrap();
        fs::write(
            case.path().join("expected-response.json"),
            r#"{"duration_ms":45000}"#,
        )
        .unwrap();
        assert_eq!(
            super::super::source_response::request_timeout(
                case.path(),
                config.target_request_timeout
            )
            .unwrap(),
            Duration::from_secs(165)
        );
        for invalid in [0, 1801] {
            project.project.replay.request_timeout_allowance_seconds = invalid;
            assert!(
                validate_project_config(&project)
                    .unwrap_err()
                    .to_string()
                    .contains("request_timeout_allowance_seconds")
            );
        }
    }

    #[test]
    fn existing_project_without_target_startup_timeout_defaults_to_180_seconds() {
        let target = target();
        initialize(options(target.path())).unwrap();
        let config_path = target.path().join(".traffic-e2e/project.yaml");
        let raw = fs::read_to_string(&config_path)
            .unwrap()
            .lines()
            .filter(|line| !line.contains("startup_timeout_seconds:"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&config_path, format!("{raw}\n")).unwrap();

        let (_, config) = resolve_project(target.path()).unwrap();

        assert_eq!(
            config.target_startup_timeout,
            Duration::from_secs(DEFAULT_TARGET_STARTUP_TIMEOUT_SECONDS)
        );
    }

    #[test]
    fn existing_project_without_replay_post_response_window_defaults_to_10ms() {
        let target = target();
        initialize(options(target.path())).unwrap();
        let config_path = target.path().join(".traffic-e2e/project.yaml");
        let raw = fs::read_to_string(&config_path)
            .unwrap()
            .lines()
            .filter(|line| !line.contains("case_dependency_post_response_window_ms:"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&config_path, format!("{raw}\n")).unwrap();

        let (_, config) = resolve_project(target.path()).unwrap();

        assert_eq!(
            config.replay_case_dependency_post_response_window,
            Duration::from_millis(
                crate::replay::DEFAULT_REPLAY_CASE_DEPENDENCY_POST_RESPONSE_WINDOW_MS
            )
        );
    }

    #[test]
    fn managed_project_resolves_runtime_outputs_without_startup_snapshot_changes() {
        let target = target();
        initialize(options(target.path())).unwrap();
        let config_path = target.path().join(".traffic-e2e/project.yaml");
        let mut project: ProjectConfig =
            serde_yaml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        project.project.target.runtime_outputs = vec![crate::runtime_output::RuntimeOutputConfig {
            id: "application-logs".to_string(),
            container_path: PathBuf::from("/data1/weibo/logs"),
            mode: crate::runtime_output::RuntimeOutputMode::ReadWrite,
            retention: crate::runtime_output::RuntimeOutputRetention::Keep,
        }];
        fs::write(config_path, serde_yaml::to_string(&project).unwrap()).unwrap();

        let (_, resolved) = resolve_project(target.path()).unwrap();

        assert_eq!(resolved.target_runtime_outputs.len(), 1);
        assert_eq!(
            resolved.target_runtime_outputs[0].container_path,
            Path::new("/data1/weibo/logs")
        );
        assert!(resolved.target_startup.mounts.is_empty());
    }

    #[test]
    fn project_rejects_target_startup_timeout_outside_the_bounded_range() {
        let target = target();
        initialize(options(target.path())).unwrap();
        let config_path = target.path().join(".traffic-e2e/project.yaml");
        let mut project: ProjectConfig =
            serde_yaml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        project.project.target.startup_timeout_seconds = 0;
        fs::write(&config_path, serde_yaml::to_string(&project).unwrap()).unwrap();

        let zero_error = resolve_project(target.path()).unwrap_err();
        assert!(
            format!("{zero_error:#}")
                .contains("startup_timeout_seconds must be between 1 and 1800")
        );

        project.project.target.startup_timeout_seconds = MAX_TARGET_STARTUP_TIMEOUT_SECONDS + 1;
        fs::write(&config_path, serde_yaml::to_string(&project).unwrap()).unwrap();

        let excessive_error = resolve_project(target.path()).unwrap_err();
        assert!(
            format!("{excessive_error:#}")
                .contains("startup_timeout_seconds must be between 1 and 1800")
        );
    }

    #[test]
    fn managed_replay_uses_the_recorder_body_limit() {
        let target = target();
        let recorder_path = target.path().join("config/project.yaml");
        let mut recorder = crate::config::AppConfig::load_static(&recorder_path).unwrap();
        recorder.recording.max_body_bytes = 1234;
        write_input_project(target.path(), &recorder);
        initialize(options(target.path())).unwrap();
        let cases = target.path().join("cases/run");
        fs::create_dir_all(&cases).unwrap();

        let (config, _) = resolve_layout(target.path(), &cases, None).unwrap();

        assert_eq!(config.target_max_response_bytes, 1234);
    }

    #[test]
    fn managed_replay_keeps_the_native_target_http_port() {
        let target = target();
        let recorder_path = target.path().join("config/project.yaml");
        let mut recorder = crate::config::AppConfig::load_static(&recorder_path).unwrap();
        recorder.http_gateway.matched_upstream = "http://127.0.0.1:8080".to_string();
        write_input_project(target.path(), &recorder);
        initialize(options(target.path())).unwrap();

        let (_, config) = resolve_project(target.path()).unwrap();

        assert_eq!(config.target_http_origin, "http://127.0.0.1:8080");
        assert_eq!(config.target_port, 8080);
    }

    #[test]
    fn managed_replay_accepts_motan_only_readiness() {
        let target = target();
        let recorder_path = target.path().join("config/project.yaml");
        let mut recorder = crate::config::AppConfig::load_static(&recorder_path).unwrap();
        recorder.http_gateway.enabled = false;
        recorder.http_gateway.ready.enabled = false;
        recorder.motan_gateway.enabled = true;
        recorder.motan_gateway.matched_upstream = "127.0.0.1:8884".to_string();
        write_input_project(target.path(), &recorder);
        initialize(options(target.path())).unwrap();

        let (_, config) = resolve_project(target.path()).unwrap();

        assert!(!config.target_http_readiness_enabled);
        assert_eq!(
            config.target_motan_upstream.as_deref(),
            Some("127.0.0.1:8884")
        );
    }

    #[test]
    fn project_quality_gates_are_not_user_configurable() {
        let target = target();
        initialize(options(target.path())).unwrap();
        let config_path = target.path().join(".traffic-e2e/project.yaml");
        let mut project: serde_yaml::Value =
            serde_yaml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        project["project"]["target"]["quality_gates"] = serde_yaml::Value::Sequence(Vec::new());
        fs::write(config_path, serde_yaml::to_string(&project).unwrap()).unwrap();

        let error = resolve_project(target.path()).unwrap_err();

        assert!(format!("{error:#}").contains("quality_gates"));
    }

    #[test]
    fn initialize_refuses_overwrite_without_explicit_replacement() {
        let target = target();
        initialize(options(target.path())).unwrap();

        let error = initialize(options(target.path())).unwrap_err();

        assert!(error.to_string().contains("refusing to replace it"));
        let mut replacement = options(target.path());
        replacement.force = true;
        let result = initialize(replacement).unwrap();
        assert!(result.replaced);
    }

    #[test]
    fn initialize_requires_existing_pr_base() {
        let target = target();
        let mut options = options(target.path());
        options.pr_base = "missing-base".to_string();

        let error = initialize(options).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("does not exist as a local branch or origin remote-tracking branch")
        );
        assert!(!target.path().join(".traffic-e2e/project.yaml").exists());
    }

    #[test]
    fn every_config_load_revalidates_pr_base() {
        let target = target();
        initialize(options(target.path())).unwrap();
        let cases = target.path().join("cases/run");
        fs::create_dir_all(&cases).unwrap();
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args(["branch", "-D", "integration"])
                .stdout(Stdio::null())
                .status()
                .unwrap()
                .success()
        );

        let error = resolve_layout(target.path(), &cases, None).unwrap_err();

        assert!(error.to_string().contains("pr_base"));
        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn obsolete_config_requires_an_explicit_future_migration() {
        let target = target();
        initialize(options(target.path())).unwrap();
        fs::write(
            target.path().join(".traffic-e2e/project.yaml"),
            "version: 2\ntarget_image: legacy\n",
        )
        .unwrap();
        let cases = target.path().join("cases/run");
        fs::create_dir_all(&cases).unwrap();

        let error = resolve_layout(target.path(), &cases, None).unwrap_err();

        assert!(error.to_string().contains("incomplete or obsolete"));
        assert!(
            error
                .to_string()
                .contains("in-place migration is not implemented")
        );
    }

    #[test]
    fn initialize_requires_internal_state_to_be_ignored() {
        let target = target();
        fs::write(target.path().join(".gitignore"), "").unwrap();

        let error = initialize(options(target.path())).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("must be ignored by the target repository")
        );
        assert!(!target.path().join(".traffic-e2e/project.yaml").exists());
    }

    #[test]
    fn missing_config_points_to_init_command() {
        let target = target();
        fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
        fs::write(target.path().join(".traffic-e2e/e2e.yaml"), "version: 4\n").unwrap();
        let cases = target.path().join("cases/run");
        fs::create_dir_all(&cases).unwrap();

        let error = resolve_layout(target.path(), &cases, None).unwrap_err();

        assert!(error.to_string().contains("project.yaml"));
        assert!(error.to_string().contains("backend-rewrite init"));
    }
}
