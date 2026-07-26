use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::model::{ProjectConfig, ResolvedProjectConfig, RunLayout};
use super::{E2eRunInitOptions, E2eRunInitResult, branch, store};
use crate::replay::validate_replay_policy;
use anyhow::{Context, Result, bail, ensure};

const CONFIG_VERSION: u32 = 5;
const DEFAULT_LOCAL_ROOT: &str = "local";
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
    ensure!(
        options.recorder_config.is_some() == options.recording_rule.is_some(),
        "recorder_config and recording_rule must be provided together"
    );
    if let Some(rule) = options.recording_rule.as_deref() {
        ensure!(!rule.trim().is_empty(), "recording_rule must not be empty");
    }

    let traffic_e2e_dir = target_root.join(".traffic-e2e");
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
    validate_replay_policy(&replay_policy).context("invalid replay policy")?;
    if let Some(recorder_config) = options.recorder_config.as_deref() {
        let recorder_config = resolve_under(&target_root, recorder_config);
        ensure!(
            recorder_config.is_file(),
            "recorder config does not exist: {}",
            recorder_config.display()
        );
        let recorder = crate::config::AppConfig::load(&recorder_config)?;
        let recording_rule = options
            .recording_rule
            .as_deref()
            .context("recording_rule is required with recorder_config")?;
        let matching_rules = recorder
            .http_gateway
            .rules
            .iter()
            .filter(|rule| rule.name.as_deref() == Some(recording_rule))
            .count();
        ensure!(
            matching_rules == 1,
            "expected exactly one recorder HTTP rule named {recording_rule:?}, found {matching_rules}"
        );
    }

    let local_root_setting = PathBuf::from(DEFAULT_LOCAL_ROOT);
    let local_root = traffic_e2e_dir.join(&local_root_setting);
    require_local_ignored(&target_root, &local_root)?;

    let project_config = ProjectConfig {
        version: CONFIG_VERSION,
        project_cli: options.project_cli,
        replay_policy: options.replay_policy,
        replay_startup_timeout_seconds: options.replay_startup_timeout_seconds,
        pr_base: options.pr_base,
        recorder_config: options.recorder_config,
        local_root: local_root_setting,
        recording_rule: options.recording_rule,
    };
    validate_project_config(&project_config)?;
    if options.force {
        store::write_yaml(&config_path, &project_config)?;
    } else {
        let mut payload = serde_yaml::to_string(&project_config)?.into_bytes();
        if !payload.ends_with(b"\n") {
            payload.push(b'\n');
        }
        crate::config::edit::create_atomic(&config_path, &payload)?;
    }
    let persisted = load_project_config(&target_root, &config_path)?;

    Ok(E2eRunInitResult {
        config: config_path,
        local_root,
        pr_base: persisted.pr_base,
        recorder_feedback: persisted.recorder_config.is_some(),
        replaced,
    })
}

pub(super) fn resolve_layout(
    target_root: &Path,
    case_source: &Path,
    explicit_run_key: Option<&str>,
) -> Result<(ResolvedProjectConfig, RunLayout)> {
    let target_root = fs::canonicalize(target_root)
        .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
    let traffic_e2e_dir = target_root.join(".traffic-e2e");
    let config_path = traffic_e2e_dir.join(PROJECT_CONFIG_FILE);
    let config = load_project_config(&target_root, &config_path)?;
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let local_root = resolve_under(&traffic_e2e_dir, &config.local_root);
    ensure!(
        local_root.starts_with(&traffic_e2e_dir) && local_root != traffic_e2e_dir,
        "local_root must be a child of .traffic-e2e"
    );
    let run_key = match explicit_run_key {
        Some(value) => validate_run_key(value)?,
        None => derive_run_key(&case_source)?,
    };
    let run_root = local_root.join(&run_key);
    let policy = validate_replay_policy(&resolve_under(&target_root, &config.replay_policy))
        .context("invalid replay policy")?;
    let resolved = ResolvedProjectConfig {
        project_cli: resolve_under(&target_root, &config.project_cli),
        replay_policy: resolve_under(&target_root, &config.replay_policy),
        replay_startup_timeout: Duration::from_secs(config.replay_startup_timeout_seconds),
        pr_base: config.pr_base,
        recorder_config: config
            .recorder_config
            .as_deref()
            .map(|path| resolve_under(&target_root, path)),
        recording_rule: config.recording_rule,
        runner_owned_response_assertions: policy.runner_owned_response_assertions,
    };
    let layout = RunLayout {
        target_root,
        run_key,
        case_source,
        progress_path: traffic_e2e_dir.join("e2e-progress.yaml"),
        local_root: local_root.clone(),
        current_path: local_root.join("current.yaml"),
        index_path: run_root.join("state.yaml"),
        group_index_path: run_root.join("case-groups.json"),
        active_dir: run_root.join(".active"),
        latest_dir: run_root.join("latest"),
        run_root,
    };
    Ok((resolved, layout))
}

pub(super) fn require_local_ignored(target_root: &Path, local_root: &Path) -> Result<()> {
    fs::create_dir_all(local_root)?;
    let probe = local_root.join(".ignore-check");
    let relative = probe
        .strip_prefix(target_root)
        .context("traffic E2E local root is outside target repository")?;
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
        local_root.display()
    );
    Ok(())
}

fn load_project_config(target_root: &Path, config_path: &Path) -> Result<ProjectConfig> {
    if !config_path.exists() {
        bail!(
            "{} is missing; run `traffic-e2e config project init \
             --target-root <target>` after recorder and replay initialization",
            config_path.display()
        );
    }
    let config: ProjectConfig = store::read_yaml(config_path).with_context(|| {
        format!(
            "{} is incomplete or obsolete; regenerate it with \
             `traffic-e2e config --target-root <target> project init --force`",
            config_path.display()
        )
    })?;
    validate_project_config(&config).with_context(|| {
        format!(
            "{} is incomplete or obsolete; regenerate it with \
             `traffic-e2e config --target-root <target> project init --force`",
            config_path.display()
        )
    })?;
    branch::validate_pr_base(target_root, &config.pr_base)?;
    Ok(config)
}

fn validate_project_config(config: &ProjectConfig) -> Result<()> {
    ensure!(
        config.version == CONFIG_VERSION,
        "unsupported traffic E2E config version {}; expected {CONFIG_VERSION}",
        config.version
    );
    ensure!(
        !config.project_cli.as_os_str().is_empty(),
        "project_cli must not be empty"
    );
    ensure!(
        !config.replay_policy.as_os_str().is_empty(),
        "replay_policy must not be empty"
    );
    ensure!(
        config.replay_startup_timeout_seconds > 0,
        "replay_startup_timeout_seconds must be greater than zero"
    );
    ensure!(
        !config.pr_base.trim().is_empty(),
        "pr_base must not be empty"
    );
    ensure!(
        !config.local_root.as_os_str().is_empty(),
        "local_root must not be empty"
    );
    ensure!(
        config.recorder_config.is_some() == config.recording_rule.is_some(),
        "recorder_config and recording_rule must be configured together"
    );
    if let Some(rule) = config.recording_rule.as_deref() {
        ensure!(!rule.trim().is_empty(), "recording_rule must not be empty");
    }
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
    use crate::e2e_run::model::DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS;

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
        fs::write(root.join(".gitignore"), ".traffic-e2e/local/\n").unwrap();
        fs::create_dir_all(root.join("scripts")).unwrap();
        let project_cli = root.join("scripts/project-cli");
        fs::write(&project_cli, "#!/usr/bin/env bash\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&project_cli, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir_all(root.join("config")).unwrap();
        fs::write(
            root.join("config/replay.yaml"),
            "version: 1\nexpected_response: assertions_only\nrules: []\n",
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
            project_cli: PathBuf::from("scripts/project-cli"),
            replay_policy: PathBuf::from("config/replay.yaml"),
            replay_startup_timeout_seconds: DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS,
            pr_base: "integration".to_string(),
            recorder_config: None,
            recording_rule: None,
            force: false,
        }
    }

    #[test]
    fn initialize_generates_valid_project_config() {
        let target = target();
        fs::remove_file(target.path().join("scripts/project-cli")).unwrap();

        let result = initialize(options(target.path())).unwrap();

        assert!(!result.replaced);
        assert!(!result.recorder_feedback);
        assert_eq!(
            result.config,
            target.path().join(".traffic-e2e/project.yaml")
        );
        assert!(!target.path().join(".traffic-e2e/e2e.yaml").exists());
        let config: ProjectConfig = store::read_yaml(&result.config).unwrap();
        assert_eq!(config.version, CONFIG_VERSION);
        assert_eq!(config.project_cli, PathBuf::from("scripts/project-cli"));
        assert_eq!(config.replay_policy, PathBuf::from("config/replay.yaml"));
        assert_eq!(
            config.replay_startup_timeout_seconds,
            DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS
        );
        assert_eq!(config.pr_base, "integration");
        assert_eq!(result.pr_base, "integration");
        assert_eq!(config.local_root, PathBuf::from(DEFAULT_LOCAL_ROOT));
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
        let repository_name = crate::repository::directory_name(root).unwrap();
        fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
        fs::write(
            root.join(".traffic-e2e/verification.yaml"),
            "version: 2\nexpected_response: assertions_only\nrules: []\n",
        )
        .unwrap();
        fs::write(
            root.join(".traffic-e2e/recorder.toml"),
            format!(
                "[[http_gateway.rules]]\nname = {:?}\nmethods = [\"GET\"]\npath_prefixes = [\"/\"]\n",
                crate::config::DEFAULT_RECORDING_RULE
            ),
        )
        .unwrap();

        let result = crate::e2e_run::initialize_standard_e2e_project(root.to_path_buf()).unwrap();
        let config: ProjectConfig = store::read_yaml(&result.config).unwrap();

        assert_eq!(
            config.project_cli,
            PathBuf::from(format!("scripts/{repository_name}-cli"))
        );
        assert!(!root.join(&config.project_cli).exists());
        assert_eq!(
            config.replay_policy,
            PathBuf::from(".traffic-e2e/verification.yaml")
        );
        assert_eq!(config.pr_base, "dev-migration");
        assert_eq!(
            config.recorder_config,
            Some(PathBuf::from(".traffic-e2e/recorder.toml"))
        );
        assert_eq!(
            config.recording_rule.as_deref(),
            Some(crate::config::DEFAULT_RECORDING_RULE)
        );
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
    fn initialize_requires_recorder_fields_as_a_pair() {
        let target = target();
        let mut options = options(target.path());
        options.recording_rule = Some("record-api".to_string());

        let error = initialize(options).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("recorder_config and recording_rule must be provided together")
        );
    }

    #[test]
    fn config_rejects_zero_replay_startup_timeout() {
        let target = target();
        initialize(options(target.path())).unwrap();
        let config_path = target.path().join(".traffic-e2e/project.yaml");
        let yaml = fs::read_to_string(&config_path).unwrap().replace(
            "replay_startup_timeout_seconds: 60",
            "replay_startup_timeout_seconds: 0",
        );
        fs::write(&config_path, yaml).unwrap();
        let cases = target.path().join("cases/run");
        fs::create_dir_all(&cases).unwrap();

        let error = resolve_layout(target.path(), &cases, None).unwrap_err();

        assert!(
            format!("{error:#}")
                .contains("replay_startup_timeout_seconds must be greater than zero")
        );
    }

    #[test]
    fn config_defaults_replay_startup_timeout_when_field_is_missing() {
        let target = target();
        initialize(options(target.path())).unwrap();
        let config_path = target.path().join(".traffic-e2e/project.yaml");
        let yaml = fs::read_to_string(&config_path)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("replay_startup_timeout_seconds:"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&config_path, format!("{yaml}\n")).unwrap();
        let cases = target.path().join("cases/run");
        fs::create_dir_all(&cases).unwrap();

        let (config, _) = resolve_layout(target.path(), &cases, None).unwrap();

        assert_eq!(
            config.replay_startup_timeout,
            Duration::from_secs(DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS)
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
    fn obsolete_config_points_to_forced_reinitialization() {
        let target = target();
        initialize(options(target.path())).unwrap();
        fs::write(
            target.path().join(".traffic-e2e/project.yaml"),
            "version: 2\n\
             project_cli: scripts/project-cli\n\
             replay_policy: config/replay.yaml\n\
             local_root: local\n",
        )
        .unwrap();
        let cases = target.path().join("cases/run");
        fs::create_dir_all(&cases).unwrap();

        let error = resolve_layout(target.path(), &cases, None).unwrap_err();

        assert!(error.to_string().contains("incomplete or obsolete"));
        assert!(
            error
                .to_string()
                .contains("traffic-e2e config --target-root <target> project init --force")
        );
    }

    #[test]
    fn initialize_requires_local_state_to_be_ignored() {
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
        assert!(
            error
                .to_string()
                .contains("traffic-e2e config project init")
        );
    }
}
