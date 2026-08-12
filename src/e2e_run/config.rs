use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::model::{
    BreezeProjectConfig, DeliveryProjectConfig, ProjectConfig, RecordingProjectConfig,
    ReplayProjectConfig, ResolvedProjectConfig, RunLayout, SourceProjectConfig, StateProjectConfig,
    TargetProjectConfig,
};
use super::target_quality_config::{inferred_target_quality_gates, validate_target_quality_gates};
use super::{E2eRunInitOptions, E2eRunInitResult, branch, store};
use crate::replay::validate_replay_policy;
use anyhow::{Context, Result, bail, ensure};

pub(super) const CONFIG_VERSION: u32 = 13;
const DEFAULT_RUNTIME_ROOT: &str = crate::internal_runtime::PROJECT_RELATIVE_ROOT;
const PROJECT_CONFIG_FILE: &str = "project.yaml";

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
        "managed project replay requires verification policy version 2 with runner-owned response assertions"
    );
    let recorder_config = resolve_under(&target_root, &options.recorder_config);
    ensure!(
        recorder_config.is_file(),
        "recorder config does not exist: {}",
        recorder_config.display()
    );
    let recorder = crate::config::AppConfig::load(&recorder_config)?;
    ensure!(
        recorder.http_gateway.ready.enabled,
        "managed project replay requires an enabled http_gateway.ready probe"
    );
    let matching_rules = recorder
        .http_gateway
        .rules
        .iter()
        .filter(|rule| rule.name.as_deref() == Some(options.recording_rule.as_str()))
        .count();
    ensure!(
        matching_rules == 1,
        "expected exactly one recorder HTTP rule named {:?}, found {matching_rules}",
        options.recording_rule
    );

    let runtime_root_setting = PathBuf::from(DEFAULT_RUNTIME_ROOT);
    let runtime_root = traffic_e2e_dir.join(&runtime_root_setting);
    require_internal_root_ignored(&target_root, &runtime_root)?;

    let payload = render_project_config(&options)?;
    let project_config: ProjectConfig = serde_yaml::from_slice(&payload)
        .context("generated project configuration is not valid YAML")?;
    if options.force {
        store::write_yaml(&config_path, &project_config)?;
    } else {
        crate::config::edit::create_atomic(&config_path, &payload)?;
    }
    let persisted = load_project_config(&target_root, &config_path)?;

    Ok(E2eRunInitResult {
        config: config_path,
        runtime_root,
        pr_base: persisted.delivery.pr_base,
        recorder_feedback: true,
        replaced,
    })
}

pub(crate) fn render_project_config(options: &E2eRunInitOptions) -> Result<Vec<u8>> {
    ensure!(
        !options.source_container.trim().is_empty(),
        "source_container must not be empty"
    );
    if let Some(container) = &options.breeze_container {
        ensure!(
            !container.trim().is_empty(),
            "breeze_container must not be empty when configured"
        );
    }
    let project_config = ProjectConfig {
        version: CONFIG_VERSION,
        source: SourceProjectConfig {
            container: options.source_container.clone(),
        },
        breeze: options
            .breeze_container
            .clone()
            .map(|container| BreezeProjectConfig { container }),
        target: TargetProjectConfig {
            dockerfile: options.target_dockerfile.clone(),
            startup: crate::startup::normalized_config(options.target_startup.clone())?,
            quality_gates: None,
        },
        replay: ReplayProjectConfig {
            policy: options.replay_policy.clone(),
        },
        recording: RecordingProjectConfig {
            config: options.recorder_config.clone(),
            rule: options.recording_rule.clone(),
        },
        delivery: DeliveryProjectConfig {
            pr_base: options.pr_base.clone(),
        },
        state: StateProjectConfig {
            runtime_root: PathBuf::from(DEFAULT_RUNTIME_ROOT),
        },
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
    let internal_root = resolve_under(&traffic_e2e_dir, &config.state.runtime_root);
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
        progress_path: traffic_e2e_dir.join("replay-progress.yaml"),
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
    let config_path = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(PROJECT_CONFIG_FILE);
    let config = load_project_config(&target_root, &config_path)?;
    let policy_path = resolve_under(&target_root, &config.replay.policy);
    let policy = validate_replay_policy(&policy_path).context("invalid replay policy")?;
    ensure!(
        policy.runner_owned_response_assertions,
        "managed project replay requires verification policy version 2 with runner-owned response assertions"
    );
    let recorder_config = resolve_under(&target_root, &config.recording.config);
    let recorder = crate::config::AppConfig::load(&recorder_config)?;
    ensure!(
        recorder.http_gateway.ready.enabled,
        "managed project replay requires an enabled http_gateway.ready probe"
    );
    let target_request_timeout = recorder
        .comparison_recording
        .as_ref()
        .map(|comparison| Duration::from_millis(comparison.upstream_timeout_ms))
        .unwrap_or_else(|| {
            Duration::from_secs(super::model::DEFAULT_TARGET_REQUEST_TIMEOUT_SECONDS)
        });
    let target_max_response_bytes = recorder.recording.max_body_bytes;
    let target_port = recorder_target_http_port(&recorder.http_gateway.matched_upstream)?;
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
    let target_quality_gates = config
        .target
        .quality_gates
        .unwrap_or_else(|| inferred_target_quality_gates(&target_root));
    Ok((
        target_root.clone(),
        ResolvedProjectConfig {
            target_dockerfile: resolve_under(&target_root, &config.target.dockerfile),
            target_startup: config.target.startup,
            target_http_origin: format!("http://127.0.0.1:{target_port}"),
            target_port,
            target_motan_upstream,
            target_readiness_path: recorder.http_gateway.ready.path,
            target_readiness_status: recorder.http_gateway.ready.success_status,
            target_startup_timeout: Duration::from_secs(
                super::model::DEFAULT_TARGET_STARTUP_TIMEOUT_SECONDS,
            ),
            target_request_timeout,
            target_quality_gates,
            target_max_response_bytes,
            source_container: config.source.container,
            breeze_container: config.breeze.map(|breeze| breeze.container),
            replay_policy: policy_path,
            replay_startup_timeout: Duration::from_secs(
                super::model::DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS,
            ),
            pr_base: config.delivery.pr_base,
            recorder_config,
            recording_rule: config.recording.rule,
            runner_owned_response_assertions: policy.runner_owned_response_assertions,
        },
    ))
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
    if !config_path.exists() {
        bail!(
            "{} is missing; from the target repository run `backend-rewrite init \
             --source-container <container> [--breeze]`",
            config_path.display()
        );
    }
    let config: ProjectConfig = store::read_yaml(config_path).with_context(|| {
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
    branch::validate_pr_base(target_root, &config.delivery.pr_base)?;
    Ok(config)
}

pub(super) fn validate_project_config(config: &ProjectConfig) -> Result<()> {
    ensure!(
        config.version == CONFIG_VERSION,
        "unsupported traffic E2E config version {}; expected {CONFIG_VERSION}",
        config.version
    );
    ensure!(
        !config.source.container.trim().is_empty(),
        "source.container must not be empty"
    );
    if let Some(breeze) = &config.breeze {
        ensure!(
            !breeze.container.trim().is_empty(),
            "breeze.container must not be empty"
        );
    }
    ensure!(
        !config.target.dockerfile.as_os_str().is_empty(),
        "target.dockerfile must not be empty"
    );
    ensure!(
        config.target.dockerfile == Path::new(".traffic-e2e/Dockerfile.e2e"),
        "target.dockerfile must be .traffic-e2e/Dockerfile.e2e"
    );
    crate::startup::validate_config(&config.target.startup)?;
    if let Some(gates) = &config.target.quality_gates {
        validate_target_quality_gates(gates)?;
    }
    ensure!(
        !config.replay.policy.as_os_str().is_empty(),
        "replay.policy must not be empty"
    );
    ensure!(
        !config.delivery.pr_base.trim().is_empty(),
        "delivery.pr_base must not be empty"
    );
    ensure!(
        config.state.runtime_root == Path::new(DEFAULT_RUNTIME_ROOT),
        "state.runtime_root must be {DEFAULT_RUNTIME_ROOT:?}"
    );
    ensure!(
        !config.recording.config.as_os_str().is_empty(),
        "recording.config must not be empty"
    );
    ensure!(
        !config.recording.rule.trim().is_empty(),
        "recording.rule must not be empty"
    );
    Ok(())
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
            root.join(".traffic-e2e/Dockerfile.e2e"),
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
            "version: 2\nexpected_response: assertions_only\nrules: []\n",
        )
        .unwrap();
        fs::write(
            root.join("config/recorder.toml"),
            "[http_gateway.ready]\nenabled = true\npath = \"/healthz\"\nsuccess_status = \
             404\n\n[[http_gateway.rules]]\nname = \"record-api\"\nmethods = \
             [\"GET\"]\npath_prefixes = [\"/\"]\n",
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

    fn options(target_root: &Path) -> E2eRunInitOptions {
        E2eRunInitOptions {
            target_root: target_root.to_path_buf(),
            source_container: "source-app".to_string(),
            breeze_container: Some("breeze".to_string()),
            target_dockerfile: PathBuf::from(".traffic-e2e/Dockerfile.e2e"),
            target_startup: crate::startup::StartupConfig::default(),
            replay_policy: PathBuf::from("config/replay.yaml"),
            pr_base: "integration".to_string(),
            recorder_config: PathBuf::from("config/recorder.toml"),
            recording_rule: "record-api".to_string(),
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
        let config: ProjectConfig = store::read_yaml(&result.config).unwrap();
        assert_eq!(config.version, CONFIG_VERSION);
        assert_eq!(config.source.container, "source-app");
        assert_eq!(
            config.target.dockerfile,
            PathBuf::from(".traffic-e2e/Dockerfile.e2e")
        );
        assert_eq!(config.replay.policy, PathBuf::from("config/replay.yaml"));
        let raw = fs::read_to_string(&result.config).unwrap();
        for duplicate in [
            "readiness_path",
            "readiness_status",
            "startup_timeout_seconds",
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
        assert_eq!(config.delivery.pr_base, "integration");
        assert_eq!(result.pr_base, "integration");
        assert_eq!(
            config.state.runtime_root,
            PathBuf::from(DEFAULT_RUNTIME_ROOT)
        );
    }

    #[test]
    fn managed_replay_uses_the_recorder_body_limit() {
        let target = target();
        let recorder_path = target.path().join("config/recorder.toml");
        let mut recorder = fs::read_to_string(&recorder_path).unwrap();
        recorder.push_str("\n[recording]\nmax_body_bytes = 1234\n");
        fs::write(recorder_path, recorder).unwrap();
        initialize(options(target.path())).unwrap();
        let cases = target.path().join("cases/run");
        fs::create_dir_all(&cases).unwrap();

        let (config, _) = resolve_layout(target.path(), &cases, None).unwrap();

        assert_eq!(config.target_max_response_bytes, 1234);
    }

    #[test]
    fn managed_replay_keeps_the_native_target_http_port() {
        let target = target();
        let recorder_path = target.path().join("config/recorder.toml");
        let recorder = fs::read_to_string(&recorder_path).unwrap().replacen(
            "[http_gateway.ready]",
            "[http_gateway]\nmatched_upstream = \"http://127.0.0.1:8080\"\n\n[http_gateway.ready]",
            1,
        );
        fs::write(recorder_path, recorder).unwrap();
        initialize(options(target.path())).unwrap();

        let (_, config) = resolve_project(target.path()).unwrap();

        assert_eq!(config.target_http_origin, "http://127.0.0.1:8080");
        assert_eq!(config.target_port, 8080);
    }

    #[test]
    fn rust_target_infers_standard_quality_gates() {
        let target = target();
        fs::write(
            target.path().join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\n",
        )
        .unwrap();
        initialize(options(target.path())).unwrap();

        let (_, config) = resolve_project(target.path()).unwrap();

        assert_eq!(
            config
                .target_quality_gates
                .iter()
                .map(|gate| gate.name.as_str())
                .collect::<Vec<_>>(),
            ["rust-format", "rust-test", "rust-clippy"]
        );
        assert_eq!(
            config.target_quality_gates[2].argv,
            [
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings"
            ]
        );
    }

    #[test]
    fn explicit_empty_quality_gates_disable_inference() {
        let target = target();
        fs::write(
            target.path().join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\n",
        )
        .unwrap();
        initialize(options(target.path())).unwrap();
        let config_path = target.path().join(".traffic-e2e/project.yaml");
        let yaml = fs::read_to_string(&config_path).unwrap().replacen(
            "  startup: {}",
            "  startup: {}\n  quality_gates: []",
            1,
        );
        fs::write(config_path, yaml).unwrap();

        let (_, config) = resolve_project(target.path()).unwrap();

        assert!(config.target_quality_gates.is_empty());
    }

    #[test]
    fn standard_initialization_uses_repository_conventions() {
        let target = target();
        let root = target.path();
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["branch", "dev-migration"])
                .status()
                .unwrap()
                .success()
        );
        fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
        fs::write(
            root.join(".traffic-e2e/verification.yaml"),
            "version: 2\nexpected_response: assertions_only\nrules: []\n",
        )
        .unwrap();
        fs::write(
            root.join(".traffic-e2e/recorder.toml"),
            format!(
                "[comparison_recording]\ncandidate_upstream = \
                 \"http://127.0.0.1:8181\"\n\n[http_gateway]\nmatched_upstream = \
                 \"http://127.0.0.1:8181\"\n\n[http_gateway.ready]\nenabled = \
                 true\npath = \"/ready\"\nsuccess_status = 200\n\n[[http_gateway.rules]]\nname = \
                 {:?}\nmethods = [\"GET\"]\npath_prefixes = [\"/\"]\n",
                crate::config::DEFAULT_RECORDING_RULE
            ),
        )
        .unwrap();

        let result = crate::e2e_run::initialize_standard_e2e_project(
            root.to_path_buf(),
            "friendship-source".to_string(),
        )
        .unwrap();
        let config: ProjectConfig = store::read_yaml(&result.config).unwrap();
        let (_, resolved) = resolve_project(root).unwrap();

        assert_eq!(
            config.target.dockerfile,
            PathBuf::from(".traffic-e2e/Dockerfile.e2e")
        );
        assert!(root.join(&config.target.dockerfile).is_file());
        assert_eq!(
            config.replay.policy,
            PathBuf::from(".traffic-e2e/verification.yaml")
        );
        assert_eq!(resolved.target_http_origin, "http://127.0.0.1:8181");
        assert_eq!(resolved.target_port, 8181);
        assert_eq!(resolved.target_readiness_path, "/ready");
        assert_eq!(resolved.target_readiness_status, 200);
        assert_eq!(resolved.target_startup_timeout, Duration::from_secs(60));
        assert_eq!(resolved.target_request_timeout, Duration::from_secs(30));
        assert_eq!(resolved.replay_startup_timeout, Duration::from_secs(60));
        assert_eq!(config.delivery.pr_base, "dev-migration");
        assert_eq!(
            config.recording.config,
            PathBuf::from(".traffic-e2e/recorder.toml")
        );
        assert_eq!(config.recording.rule, crate::config::DEFAULT_RECORDING_RULE);
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
    fn initialize_requires_source_container() {
        let target = target();
        let mut options = options(target.path());
        options.source_container.clear();

        let error = initialize(options).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("source_container must not be empty")
        );
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
            "version: 2\n\
             target_image: legacy\n\
             replay_policy: config/replay.yaml\n\
             ai_forbidden_root: .ai-forbidden\n",
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
