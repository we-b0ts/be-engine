use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail, ensure};

use super::model::{ProjectConfig, ResolvedProjectConfig, RunLayout};
use super::{E2eRunInitOptions, E2eRunInitResult, require_executable, store};
use crate::replay::validate_replay_policy;

const CONFIG_VERSION: u32 = 3;
const DEFAULT_LOCAL_ROOT: &str = "local";

pub(super) fn initialize(options: E2eRunInitOptions) -> Result<E2eRunInitResult> {
    let target_root = fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    validate_integration_branch(&target_root, &options.integration_branch)?;
    ensure!(
        options.recorder_config.is_some() == options.recording_rule.is_some(),
        "recorder_config and recording_rule must be provided together"
    );
    if let Some(rule) = options.recording_rule.as_deref() {
        ensure!(!rule.trim().is_empty(), "recording_rule must not be empty");
    }

    let migration_dir = target_root.join(".migration");
    let config_path = migration_dir.join("e2e.yaml");
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
            "{} already exists; use --force to replace it explicitly",
            config_path.display()
        );
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "{} must be a regular file and not a symlink",
            config_path.display()
        );
    }

    let project_cli = resolve_under(&target_root, &options.project_cli);
    require_executable(&project_cli, "project CLI")?;
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
    }

    let local_root_setting = PathBuf::from(DEFAULT_LOCAL_ROOT);
    let local_root = migration_dir.join(&local_root_setting);
    require_local_ignored(&target_root, &local_root)?;

    let project_config = ProjectConfig {
        version: CONFIG_VERSION,
        project_cli: options.project_cli,
        replay_policy: options.replay_policy,
        integration_branch: options.integration_branch,
        recorder_config: options.recorder_config,
        local_root: local_root_setting,
        recording_rule: options.recording_rule,
        _legacy_required_consecutive_successful_runs: None,
    };
    store::write_yaml(&config_path, &project_config)?;
    let persisted = load_project_config(&target_root, &config_path)?;

    Ok(E2eRunInitResult {
        config: config_path,
        local_root,
        integration_branch: persisted.integration_branch,
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
    let migration_dir = target_root.join(".migration");
    let config_path = migration_dir.join("e2e.yaml");
    let config = load_project_config(&target_root, &config_path)?;
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let local_root = resolve_under(&migration_dir, &config.local_root);
    ensure!(
        local_root.starts_with(&migration_dir) && local_root != migration_dir,
        "migration local_root must be a child of .migration"
    );
    let run_key = match explicit_run_key {
        Some(value) => validate_run_key(value)?,
        None => derive_run_key(&case_source)?,
    };
    let run_root = local_root.join(&run_key);
    let resolved = ResolvedProjectConfig {
        project_cli: resolve_under(&target_root, &config.project_cli),
        replay_policy: resolve_under(&target_root, &config.replay_policy),
        recorder_config: config
            .recorder_config
            .as_deref()
            .map(|path| resolve_under(&target_root, path)),
        recording_rule: config.recording_rule,
    };
    let layout = RunLayout {
        target_root,
        run_key,
        case_source,
        progress_path: migration_dir.join("e2e-progress.yaml"),
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
        .context("migration local root is outside target repository")?;
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
        "{} must be ignored by the target repository before running migration E2E",
        local_root.display()
    );
    Ok(())
}

fn load_project_config(target_root: &Path, config_path: &Path) -> Result<ProjectConfig> {
    if !config_path.exists() {
        bail!(
            "{} is missing; run `traffic-e2e-run init --target-root <target> \
             --project-cli <path> --replay-policy <path> \
             --integration-branch <branch>` with confirmed project settings",
            config_path.display()
        );
    }
    let config: ProjectConfig = store::read_yaml(config_path).with_context(|| {
        format!(
            "{} is incomplete or obsolete; rerun `traffic-e2e-run init --force` \
             with confirmed project settings",
            config_path.display()
        )
    })?;
    validate_project_config(&config).with_context(|| {
        format!(
            "{} is incomplete or obsolete; rerun `traffic-e2e-run init --force` \
             with confirmed project settings",
            config_path.display()
        )
    })?;
    validate_integration_branch(target_root, &config.integration_branch)?;
    Ok(config)
}

fn validate_project_config(config: &ProjectConfig) -> Result<()> {
    ensure!(
        config.version == CONFIG_VERSION,
        "unsupported migration config version {}; expected {CONFIG_VERSION}",
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
        !config.integration_branch.trim().is_empty(),
        "integration_branch must not be empty"
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

fn validate_integration_branch(target_root: &Path, branch: &str) -> Result<()> {
    ensure!(
        branch == branch.trim() && !branch.is_empty(),
        "integration_branch must be a non-empty branch name without surrounding whitespace"
    );
    let valid = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .arg("check-ref-format")
        .arg("--branch")
        .arg(branch)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to validate integration_branch with git")?;
    ensure!(
        valid.success(),
        "integration_branch is not a valid Git branch name: {branch}"
    );
    let local = git_ref_exists(target_root, &format!("refs/heads/{branch}^{{commit}}"))?;
    let remote = git_ref_exists(
        target_root,
        &format!("refs/remotes/origin/{branch}^{{commit}}"),
    )?;
    ensure!(
        local || remote,
        "integration_branch {branch:?} does not exist as a local branch or origin remote-tracking branch"
    );
    Ok(())
}

fn git_ref_exists(target_root: &Path, reference: &str) -> Result<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .arg("rev-parse")
        .arg("--verify")
        .arg("--quiet")
        .arg(reference)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to resolve Git reference {reference}"))?;
    Ok(status.success())
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
        fs::write(root.join(".gitignore"), ".migration/local/\n").unwrap();
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
            integration_branch: "integration".to_string(),
            recorder_config: None,
            recording_rule: None,
            force: false,
        }
    }

    #[test]
    fn initialize_generates_valid_project_config() {
        let target = target();

        let result = initialize(options(target.path())).unwrap();

        assert!(!result.replaced);
        assert!(!result.recorder_feedback);
        assert_eq!(result.config, target.path().join(".migration/e2e.yaml"));
        let config: ProjectConfig = store::read_yaml(&result.config).unwrap();
        assert_eq!(config.version, CONFIG_VERSION);
        assert_eq!(config.project_cli, PathBuf::from("scripts/project-cli"));
        assert_eq!(config.replay_policy, PathBuf::from("config/replay.yaml"));
        assert_eq!(config.integration_branch, "integration");
        assert_eq!(result.integration_branch, "integration");
        assert_eq!(config.local_root, PathBuf::from(DEFAULT_LOCAL_ROOT));
        let yaml = fs::read_to_string(&result.config).unwrap();
        assert!(!yaml.contains("required_consecutive_successful_runs"));
    }

    #[test]
    fn initialize_refuses_overwrite_without_force() {
        let target = target();
        initialize(options(target.path())).unwrap();

        let error = initialize(options(target.path())).unwrap_err();

        assert!(error.to_string().contains("use --force"));
        let mut replacement = options(target.path());
        replacement.force = true;
        let result = initialize(replacement).unwrap();
        assert!(result.replaced);
    }

    #[test]
    fn accepts_legacy_successful_run_setting_without_persisting_it() {
        let target = target();
        let mut generated = options(target.path());
        generated.force = false;
        let result = initialize(generated).unwrap();
        let mut yaml = fs::read_to_string(&result.config).unwrap();
        yaml.push_str("required_consecutive_successful_runs: 3\n");
        fs::write(&result.config, yaml).unwrap();
        let cases = target.path().join("cases/run");
        fs::create_dir_all(&cases).unwrap();

        resolve_layout(target.path(), &cases, None).unwrap();

        let mut replacement = options(target.path());
        replacement.force = true;
        initialize(replacement).unwrap();
        let yaml = fs::read_to_string(&result.config).unwrap();
        assert!(!yaml.contains("required_consecutive_successful_runs"));
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
    fn initialize_requires_existing_integration_branch() {
        let target = target();
        let mut options = options(target.path());
        options.integration_branch = "missing-base".to_string();

        let error = initialize(options).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("does not exist as a local branch or origin remote-tracking branch")
        );
        assert!(!target.path().join(".migration/e2e.yaml").exists());
    }

    #[test]
    fn every_config_load_revalidates_integration_branch() {
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

        assert!(error.to_string().contains("integration_branch"));
        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn obsolete_config_points_to_forced_reinitialization() {
        let target = target();
        initialize(options(target.path())).unwrap();
        fs::write(
            target.path().join(".migration/e2e.yaml"),
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
        assert!(error.to_string().contains("traffic-e2e-run init --force"));
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
        assert!(!target.path().join(".migration/e2e.yaml").exists());
    }

    #[test]
    fn missing_config_points_to_init_command() {
        let target = target();
        let cases = target.path().join("cases/run");
        fs::create_dir_all(&cases).unwrap();

        let error = resolve_layout(target.path(), &cases, None).unwrap_err();

        assert!(error.to_string().contains("traffic-e2e-run init"));
        assert!(error.to_string().contains("--project-cli"));
        assert!(error.to_string().contains("--replay-policy"));
        assert!(error.to_string().contains("--integration-branch"));
    }
}
