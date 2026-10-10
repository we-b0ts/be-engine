use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::initialization::{RecorderConfigInitOptions, render_validated_recorder_config};
use crate::e2e_run::{E2eRunInitOptions, render_project_config};

mod target_template;

use target_template::{render_target_main, render_target_startup_probe};

const PROJECT_CONFIG_PATH: &str = ".traffic-e2e/project.yaml";
const SOURCE_TRAFFIC_POLICY_PATH: &str = ".traffic-e2e/source-traffic-policy.yaml";
const VERIFICATION_POLICY_PATH: &str = ".traffic-e2e/verification.yaml";
const TARGET_CARGO_PATH: &str = "Cargo.toml";
const TARGET_CARGO_LOCK_PATH: &str = "Cargo.lock";
const TARGET_MAIN_PATH: &str = "src/main.rs";
const TARGET_STARTUP_PROBE_PATH: &str = "src/startup_probe.rs";
const SOURCE_DOCKERFILE_PATH: &str = ".traffic-e2e/Dockerfile.source";
const TARGET_DOCKERFILE_PATH: &str = ".traffic-e2e/Dockerfile.target";
const TARGET_GITIGNORE_PATH: &str = ".gitignore";
const TARGET_DOCKERIGNORE_PATH: &str = ".dockerignore";
const LOCAL_DIR: &str = crate::repository::LOCAL_ROOT;
const PR_BASE: &str = "dev-migration";
const TARGET_CARGO_TEMPLATE: &str = include_str!("templates/target/Cargo.toml");
const TARGET_CARGO_LOCK_TEMPLATE: &str = include_str!("templates/target/Cargo.lock");
const TARGET_MAIN_TEMPLATE: &str = include_str!("templates/target/src/main.rs");
const TARGET_STARTUP_PROBE_TEMPLATE: &str = include_str!("templates/target/src/startup_probe.rs");
const SOURCE_DOCKERFILE_TEMPLATE: &str = include_str!("templates/source/Dockerfile.source");
const TARGET_DOCKERFILE_TEMPLATE: &str = include_str!("templates/target/Dockerfile.target");
const TARGET_TEMPLATE_PACKAGE: &str = "traffic-e2e-target-template";
const TARGET_TEMPLATE_CACHE_ID: &str = "traffic-e2e-template-target";
const TARGET_GITIGNORE_RULES: &[&str] = &[
    crate::repository::LOCAL_GITIGNORE_RULE,
    crate::config::regression::GITIGNORE_RULE,
    "/target/",
    "**/target/",
    "/data/",
    "/recordings/",
    "**/recordings/",
    "*.pem",
    "*.key",
    "*.jks",
    "*.p12",
    "*.pfx",
    ".env",
    ".env.*",
];
const TARGET_DOCKERIGNORE_RULES: &[&str] = &[
    "/.git/",
    "/.traffic-e2e/local/",
    crate::config::regression::GITIGNORE_RULE,
    "/target/",
    "**/target/",
    "/data/",
    "/recordings/",
    "**/recordings/",
    "*.pem",
    "*.key",
    "*.jks",
    "*.p12",
    "*.pfx",
    ".env",
    ".env.*",
];

#[derive(Debug, Clone)]
pub struct RepositoryConfigInitOptions {
    pub target_root: PathBuf,
    pub source: crate::SourceOptions,
    pub http_backend_port: u16,
    pub http_gateway_port: u16,
    pub readiness_path: String,
    pub upstream_dns: SocketAddr,
    pub env_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepositoryConfigInitResult {
    pub target_root: PathBuf,
    pub generated: Vec<PathBuf>,
    pub source_snapshot: crate::SourceSnapshotReport,
    pub upstream_dns: SocketAddr,
    pub http_backend_port: u16,
    pub http_gateway_port: u16,
    pub local_dir: PathBuf,
    pub target_environment: PathBuf,
    pub gitignore: PathBuf,
    pub gitignore_updated: bool,
    pub dockerignore: PathBuf,
    pub dockerignore_updated: bool,
    pub startup: crate::startup::StartupSnapshotReport,
    pub source_dockerfile: PathBuf,
    pub target_dockerfile: PathBuf,
    pub target_image_tag: String,
    pub target_runtime_contract: &'static str,
    pub rewrite_command: &'static str,
    pub preflight_command: &'static str,
    pub record_command: &'static str,
}

pub fn initialize_repository_config(
    options: RepositoryConfigInitOptions,
) -> Result<RepositoryConfigInitResult> {
    initialize_repository_config_with(
        options,
        crate::capture_source_snapshot,
        crate::startup::capture_startup_snapshot,
    )
}

fn initialize_repository_config_with(
    options: RepositoryConfigInitOptions,
    capture_source: impl Fn(&Path, &crate::SourceOptions) -> Result<crate::SourceSnapshotReport>,
    capture_startup: impl Fn(
        &Path,
        &crate::startup::StartupConfig,
    ) -> Result<crate::startup::StartupSnapshotReport>,
) -> Result<RepositoryConfigInitResult> {
    let target_root = std::fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    let configuration_targets = [
        PROJECT_CONFIG_PATH,
        SOURCE_TRAFFIC_POLICY_PATH,
        VERIFICATION_POLICY_PATH,
    ]
    .map(|relative| target_root.join(relative));
    require_configuration_targets_absent(&configuration_targets)?;
    ensure_pr_base_branch(&target_root)?;

    let recorder_options = RecorderConfigInitOptions {
        target_root: target_root.clone(),
        source_http_port: options.http_backend_port,
        http_gateway_port: options.http_gateway_port,
        readiness_path: options.readiness_path.clone(),
        upstream_dns: options.upstream_dns,
        platform_response_rewrite_enabled: false,
    };
    let (_, recorder) = render_validated_recorder_config(&recorder_options)?;
    let verification = crate::replay::render_validated_replay_policy()?;
    let recorder = serde_yaml::from_str::<super::AppConfig>(&recorder)
        .context("generated recorder config is not valid YAML")?;
    let project = render_project_config(
        &E2eRunInitOptions {
            target_root: target_root.clone(),
            target_dockerfile: PathBuf::from(TARGET_DOCKERFILE_PATH),
            target_startup: crate::startup::StartupConfig::default(),
            replay_policy: PathBuf::from(VERIFICATION_POLICY_PATH),
            pr_base: PR_BASE.to_string(),
            recorder_config: PathBuf::from(PROJECT_CONFIG_PATH),
            force: false,
        },
        recorder,
    )?;
    let source_traffic_policy = super::SourceTrafficPolicyConfig::repository_defaults().render()?;

    let (gitignore, gitignore_updated, gitignore_created) = ensure_target_gitignore(&target_root)?;
    let (dockerignore, dockerignore_updated, dockerignore_created) =
        ensure_target_dockerignore(&target_root)?;
    let mut target_files = render_missing_target_delivery(&target_root, &options)?;
    let source_snapshot = capture_source(&target_root, &options.source)?;
    let target_environment =
        crate::startup::initialize_startup_environment(&target_root, options.env_file.as_deref())?;
    let startup = crate::startup::StartupConfig::default();
    let startup = capture_startup(&target_root, &startup)?;
    let mut files = vec![
        (configuration_targets[0].clone(), project),
        (
            configuration_targets[1].clone(),
            source_traffic_policy.into_bytes(),
        ),
        (configuration_targets[2].clone(), verification.into_bytes()),
    ];
    let regression = target_root.join(crate::config::regression::PATH);
    if !regression.exists() {
        files.push((
            regression,
            crate::config::regression::TEMPLATE.as_bytes().to_vec(),
        ));
    }
    files.append(&mut target_files);
    let mut generated = files
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    if dockerignore_created {
        generated.push(dockerignore.clone());
    }
    if gitignore_created {
        generated.push(gitignore.clone());
    }
    super::edit::create_many_atomic(&files)?;
    let target_image_tag = crate::target_container::image_tag(&target_root)?;

    Ok(RepositoryConfigInitResult {
        target_root,
        generated,
        source_snapshot,
        upstream_dns: options.upstream_dns,
        http_backend_port: options.http_backend_port,
        http_gateway_port: options.http_gateway_port,
        local_dir: PathBuf::from(LOCAL_DIR),
        target_environment: target_environment.path,
        gitignore,
        gitignore_updated,
        dockerignore,
        dockerignore_updated,
        startup,
        source_dockerfile: PathBuf::from(SOURCE_DOCKERFILE_PATH),
        target_dockerfile: PathBuf::from(TARGET_DOCKERFILE_PATH),
        target_image_tag,
        target_runtime_contract: "traffic-e2e builds Dockerfile.target, runs its OCI entrypoint as \
                                  998:998 with the captured source application environment plus \
                                  target.env overrides and source-compatible startup mounts, \
                                  and owns readiness, signals, network namespace, and cleanup",
        rewrite_command: "backend-rewrite next --api '<METHOD path-or-pattern>'",
        preflight_command: "traffic-e2e diagnose preflight",
        record_command: "traffic-e2e record --config .traffic-e2e/project.yaml -- /app/start-source",
    })
}

#[derive(Debug, Deserialize)]
struct TargetCargoManifest {
    package: Option<TargetCargoPackage>,
    #[serde(default)]
    bin: Vec<TargetCargoBin>,
}

#[derive(Debug, Deserialize)]
struct TargetCargoPackage {
    name: String,
    #[serde(rename = "default-run")]
    default_run: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TargetCargoBin {
    name: Option<String>,
}

fn render_missing_target_delivery(
    target_root: &Path,
    options: &RepositoryConfigInitOptions,
) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let cargo = target_root.join(TARGET_CARGO_PATH);
    let cargo_lock = target_root.join(TARGET_CARGO_LOCK_PATH);
    let main = target_root.join(TARGET_MAIN_PATH);
    let source_dockerfile = target_root.join(SOURCE_DOCKERFILE_PATH);
    let dockerfile = target_root.join(TARGET_DOCKERFILE_PATH);
    let cargo_exists = path_exists(&cargo)?;
    let cargo_lock_exists = path_exists(&cargo_lock)?;
    let main_exists = path_exists(&main)?;
    let source_dockerfile_exists = path_exists(&source_dockerfile)?;
    let dockerfile_exists = path_exists(&dockerfile)?;

    let template_target = !cargo_exists && !cargo_lock_exists && !main_exists;
    ensure!(
        template_target || cargo_exists && cargo_lock_exists && main_exists,
        "target initialization requires Cargo.toml, Cargo.lock, and src/main.rs to either all exist or all be absent"
    );

    let binary = if template_target {
        target_package_name(target_root)?
    } else {
        require_regular_file(&cargo, "target Cargo.toml")?;
        require_regular_file(&cargo_lock, "target Cargo.lock")?;
        require_regular_file(&main, "target src/main.rs")?;
        target_binary_name(&cargo)?
    };
    validate_target_binary_name(&binary)?;

    let mut files = Vec::new();
    if !source_dockerfile_exists {
        files.push((
            source_dockerfile,
            SOURCE_DOCKERFILE_TEMPLATE.as_bytes().to_vec(),
        ));
    } else {
        require_regular_file(&source_dockerfile, "source Dockerfile")?;
    }
    if template_target {
        files.push((
            cargo,
            TARGET_CARGO_TEMPLATE
                .replace(TARGET_TEMPLATE_PACKAGE, &binary)
                .into_bytes(),
        ));
        files.push((
            cargo_lock,
            TARGET_CARGO_LOCK_TEMPLATE
                .replace(TARGET_TEMPLATE_PACKAGE, &binary)
                .into_bytes(),
        ));
        files.push((
            main,
            render_target_main(&options.readiness_path, options.http_backend_port)?.into_bytes(),
        ));
        files.push((
            target_root.join(TARGET_STARTUP_PROBE_PATH),
            render_target_startup_probe().into_bytes(),
        ));
    }
    if !dockerfile_exists {
        let project = target_cache_project(target_root)?;
        let dockerfile = TARGET_DOCKERFILE_TEMPLATE
            .replace(
                TARGET_TEMPLATE_CACHE_ID,
                &format!("traffic-e2e-{project}-target"),
            )
            .replace(TARGET_TEMPLATE_PACKAGE, &binary);
        files.push((
            target_root.join(TARGET_DOCKERFILE_PATH),
            dockerfile.into_bytes(),
        ));
    } else {
        require_regular_file(&dockerfile, "target Dockerfile")?;
    }
    Ok(files)
}

fn path_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink: {}",
        path.display()
    );
    Ok(())
}

fn target_package_name(target_root: &Path) -> Result<String> {
    let name = crate::repository::directory_name(target_root)?;
    let mut normalized = String::with_capacity(name.len());
    let mut previous_separator = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
            previous_separator = false;
        } else if !previous_separator {
            normalized.push('-');
            previous_separator = true;
        }
    }
    let normalized = normalized.trim_matches('-').to_string();
    ensure!(
        !normalized.is_empty(),
        "target repository name cannot form a Cargo package name"
    );
    Ok(normalized)
}

fn target_binary_name(cargo_path: &Path) -> Result<String> {
    let contents = std::fs::read_to_string(cargo_path)
        .with_context(|| format!("failed to read {}", cargo_path.display()))?;
    let manifest: TargetCargoManifest = toml::from_str(&contents)
        .with_context(|| format!("failed to parse {}", cargo_path.display()))?;
    let package = manifest
        .package
        .context("target Cargo.toml must contain [package] when Dockerfile.target is generated")?;
    if let Some(default_run) = package.default_run {
        return Ok(default_run);
    }
    let named_bins = manifest
        .bin
        .into_iter()
        .filter_map(|binary| binary.name)
        .collect::<Vec<_>>();
    if named_bins.len() == 1 {
        return Ok(named_bins.into_iter().next().expect("one named binary"));
    }
    Ok(package.name)
}

fn validate_target_binary_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "target binary name contains unsupported Dockerfile characters: {name:?}"
    );
    Ok(())
}

fn target_cache_project(target_root: &Path) -> Result<String> {
    let tag = crate::target_container::image_tag(target_root)?;
    tag.strip_prefix("traffic-e2e/")
        .and_then(|value| value.strip_suffix("-target:cache"))
        .map(str::to_string)
        .context("failed to derive target cache identity")
}

fn require_configuration_targets_absent(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Ok(_) => anyhow::bail!(
                "{} already exists; refusing to initialize any configuration",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        }
    }
    Ok(())
}

fn ensure_pr_base_branch(target_root: &Path) -> Result<()> {
    let reference = format!("refs/heads/{PR_BASE}");
    let exists = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(["show-ref", "--verify", "--quiet", &reference])
        .status()
        .context("failed to inspect the initialization pull-request base branch")?;
    if exists.success() {
        return Ok(());
    }
    ensure!(
        exists.code() == Some(1),
        "failed to inspect the initialization pull-request base branch"
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(["branch", PR_BASE, "HEAD"])
        .output()
        .context("failed to create the initialization pull-request base branch")?;
    ensure!(
        output.status.success(),
        "failed to create pr_base {PR_BASE:?} from HEAD: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn ensure_target_dockerignore(target_root: &Path) -> Result<(PathBuf, bool, bool)> {
    ensure_ignore_rules(
        target_root,
        TARGET_DOCKERIGNORE_PATH,
        TARGET_DOCKERIGNORE_RULES,
    )
}

fn ensure_target_gitignore(target_root: &Path) -> Result<(PathBuf, bool, bool)> {
    let result = ensure_ignore_rules(target_root, TARGET_GITIGNORE_PATH, TARGET_GITIGNORE_RULES)?;
    require_ignored(target_root, LOCAL_DIR)?;
    Ok(result)
}

fn ensure_ignore_rules(
    target_root: &Path,
    relative_path: &str,
    rules: &[&str],
) -> Result<(PathBuf, bool, bool)> {
    let path = target_root.join(relative_path);
    let (mut contents, exists) = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "{} must be a regular file and not a symlink",
                path.display()
            );
            (
                std::fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?,
                true,
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (String::new(), false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    let missing = rules
        .iter()
        .filter(|rule| !contents.lines().any(|line| line.trim() == **rule))
        .copied()
        .collect::<Vec<_>>();
    let updated = !missing.is_empty();
    if updated {
        if !contents.is_empty() && !contents.ends_with('\n') {
            contents.push('\n');
        }
        for rule in missing {
            contents.push_str(rule);
            contents.push('\n');
        }
        if exists {
            super::edit::write_atomic(&path, contents.as_bytes())?;
        } else {
            super::edit::create_atomic(&path, contents.as_bytes())?;
        }
    }
    Ok((path, updated, !exists))
}

fn require_ignored(target_root: &Path, relative_dir: &str) -> Result<()> {
    let probe = format!("{relative_dir}/.ignore-check");
    let status = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(["check-ignore", "-q", "--"])
        .arg(&probe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to run git check-ignore")?;
    ensure!(
        status.success(),
        "{relative_dir}/ must be ignored by the target repository before initialization"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use tempfile::tempdir;

    use super::*;
    use crate::config::DEFAULT_BODY_LIMIT_BYTES;

    fn source_options() -> crate::SourceOptions {
        crate::SourceOptions::Kubernetes(crate::KubernetesSourceOptions {
            pod: "friendship".to_string(),
            namespace: "wb-plat-ide".to_string(),
            container: None,
            kubeconfig: None,
            context: None,
            kubectl_binary: PathBuf::from("kubectl"),
        })
    }

    #[test]
    fn conventional_paths_are_bounded_and_startup_is_captured() {
        assert_eq!(LOCAL_DIR, ".traffic-e2e/local");
        assert_eq!(
            crate::repository::LOCAL_STARTUP_ROOT,
            ".traffic-e2e/local/startup"
        );
        assert_eq!(
            crate::internal_runtime::REPOSITORY_RELATIVE_ROOT,
            ".traffic-e2e/local/runtime"
        );
        assert_eq!(
            [
                PROJECT_CONFIG_PATH,
                SOURCE_TRAFFIC_POLICY_PATH,
                VERIFICATION_POLICY_PATH
            ],
            [
                ".traffic-e2e/project.yaml",
                ".traffic-e2e/source-traffic-policy.yaml",
                ".traffic-e2e/verification.yaml"
            ]
        );
    }

    #[test]
    fn unified_init_creates_dev_migration_from_head_without_switching() {
        let target = tempdir().unwrap();
        fs::write(target.path().join("README.md"), "# target\n").unwrap();
        let environment = target.path().join("input.env");
        fs::write(&environment, "DATABASE_URL='postgres://local/$db'\n").unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q", "-b", "initialization-work"])
                .arg(target.path())
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args([
                    "-c",
                    "user.name=E2E Test",
                    "-c",
                    "user.email=e2e-test@example.invalid",
                    "add",
                    "README.md",
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
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
        let capture_source = |_root: &Path, options: &crate::SourceOptions| {
            let crate::SourceOptions::Kubernetes(options) = options else {
                panic!("expected Kubernetes source");
            };
            Ok(crate::SourceSnapshotReport {
                status: "captured",
                snapshot_id: "source-snapshot-test".to_string(),
                root: PathBuf::from(crate::repository::LOCAL_SOURCE_ROOT),
                provider: crate::SourceProviderEvidence::KubernetesPod {
                    context: None,
                    namespace: options.namespace.clone(),
                    pod: options.pod.clone(),
                    pod_uid: "pod-uid".to_string(),
                    container: "app".to_string(),
                    restart_count: 0,
                },
                image: crate::SourceImage {
                    reference: "example/app:1".to_string(),
                    registry_digest: Some(format!("example/app@sha256:{}", "a".repeat(64))),
                    archive_sha256: None,
                    local_id: format!("sha256:{}", "b".repeat(64)),
                    architecture: "amd64".to_string(),
                    os: "linux".to_string(),
                },
                environment_variables: 2,
                target_environment_variables: 1,
                mounts: Vec::new(),
                ignored_mounts: Vec::new(),
            })
        };
        let capture = |_target_root: &Path, config: &crate::startup::StartupConfig| {
            Ok(crate::startup::StartupSnapshotReport {
                status: "captured",
                snapshot_id: "snapshot-test".to_string(),
                root: PathBuf::from(crate::repository::LOCAL_STARTUP_ROOT),
                mounts: config.mounts.clone(),
                writable_mounts: Vec::new(),
                source_snapshot_id: "source-snapshot-test".to_string(),
                source_image_id: "image-id".to_string(),
            })
        };
        let result = initialize_repository_config_with(
            RepositoryConfigInitOptions {
                target_root: target.path().to_path_buf(),
                source: source_options(),
                http_backend_port: 8_181,
                http_gateway_port: 4_080,
                readiness_path: "/healthz".to_string(),
                upstream_dns: "10.10.10.11:53".parse().unwrap(),
                env_file: Some(environment),
            },
            capture_source,
            capture,
        )
        .unwrap();

        assert_eq!(result.generated.len(), 12);
        assert!(
            result
                .generated
                .contains(&target.path().join(crate::config::regression::PATH))
        );
        assert_eq!(result.http_backend_port, 8_181);
        assert_eq!(result.http_gateway_port, 4_080);
        assert_eq!(result.local_dir, PathBuf::from(LOCAL_DIR));
        assert_eq!(
            result.target_environment,
            PathBuf::from(crate::repository::LOCAL_TARGET_ENV_PATH)
        );
        assert!(target.path().join(&result.target_environment).is_file());
        assert!(
            crate::startup::startup_environment_equals(
                target.path(),
                "DATABASE_URL",
                "postgres://local/$db",
            )
            .unwrap()
            .equal
        );
        assert_eq!(result.gitignore, target.path().join(".gitignore"));
        assert!(result.gitignore_updated);
        assert_eq!(result.dockerignore, target.path().join(".dockerignore"));
        assert!(result.dockerignore_updated);
        let gitignore = fs::read_to_string(&result.gitignore).unwrap();
        for rule in TARGET_GITIGNORE_RULES {
            assert!(gitignore.lines().any(|line| line == *rule));
        }
        let (_, updated, created) = ensure_target_gitignore(target.path()).unwrap();
        assert!(!updated);
        assert!(!created);
        assert_eq!(fs::read_to_string(&result.gitignore).unwrap(), gitignore);
        assert_eq!(
            result.rewrite_command,
            "backend-rewrite next --api '<METHOD path-or-pattern>'"
        );
        assert_eq!(result.preflight_command, "traffic-e2e diagnose preflight");
        assert_eq!(
            result.source_dockerfile,
            PathBuf::from(".traffic-e2e/Dockerfile.source")
        );
        assert_eq!(
            result.target_dockerfile,
            PathBuf::from(".traffic-e2e/Dockerfile.target")
        );
        assert!(result.target_image_tag.ends_with("-target:cache"));
        assert!(target.path().join(PROJECT_CONFIG_PATH).is_file());
        assert!(target.path().join(SOURCE_TRAFFIC_POLICY_PATH).is_file());
        assert!(target.path().join(VERIFICATION_POLICY_PATH).is_file());
        assert!(target.path().join(TARGET_CARGO_PATH).is_file());
        assert!(target.path().join(TARGET_CARGO_LOCK_PATH).is_file());
        assert!(target.path().join(TARGET_MAIN_PATH).is_file());
        assert!(target.path().join(TARGET_STARTUP_PROBE_PATH).is_file());
        assert!(target.path().join(SOURCE_DOCKERFILE_PATH).is_file());
        assert!(target.path().join(TARGET_DOCKERFILE_PATH).is_file());
        let cargo = fs::read_to_string(target.path().join(TARGET_CARGO_PATH)).unwrap();
        assert!(cargo.contains("brz-logs = { version = \"=0.0.6\""));
        assert!(cargo.contains("features = [\"metrics\"]"));
        assert!(
            cargo.contains("http-server = { package = \"brz-http-server\", version = \"=0.0.13\"")
        );
        let lock = fs::read_to_string(target.path().join(TARGET_CARGO_LOCK_PATH)).unwrap();
        assert!(lock.contains("name = \"brz-logs\""));
        assert!(lock.contains("name = \"brz-http-server\""));
        assert!(!lock.contains("git+ssh://git@git.intra.demo.test"));
        let main = fs::read_to_string(target.path().join(TARGET_MAIN_PATH)).unwrap();
        assert!(!main.contains("TARGET_PORT_ENV"));
        assert!(main.contains("#[http_server::get(\"/healthz\", group = readiness_apis)]"));
        assert!(main.contains("http_server::handlers!(; group = readiness_apis)"));
        assert!(main.contains("StatusCode::OK"));
        assert!(main.contains("Delete this module declaration"));
        assert!(main.contains("startup_probe::run().await?;"));
        let probe = fs::read_to_string(target.path().join(TARGET_STARTUP_PROBE_PATH)).unwrap();
        assert!(probe.contains(crate::network_probe::ORIGIN_HEADER));
        assert!(probe.contains(crate::network_probe::TARGET_ORIGIN));
        let source_dockerfile =
            fs::read_to_string(target.path().join(SOURCE_DOCKERFILE_PATH)).unwrap();
        assert!(source_dockerfile.contains("ARG SOURCE_IMAGE"));
        assert!(source_dockerfile.contains("FROM ${SOURCE_IMAGE}"));
        assert!(source_dockerfile.contains("USER 998:998"));
        assert!(!source_dockerfile.contains("java"));
        let dockerfile = fs::read_to_string(target.path().join(TARGET_DOCKERFILE_PATH)).unwrap();
        assert!(dockerfile.contains("COPY Cargo.toml Cargo.lock ./"));
        assert!(dockerfile.contains("COPY src ./src"));
        assert!(!dockerfile.contains("COPY . ."));
        assert!(!dockerfile.contains("--mount=type=ssh"));
        assert!(!dockerfile.contains("git ls-remote"));
        assert!(!dockerfile.contains("git.intra.demo.test"));
        assert!(!dockerfile.contains("__TARGET_"));
        for rule in TARGET_DOCKERIGNORE_RULES {
            assert!(
                fs::read_to_string(&result.dockerignore)
                    .unwrap()
                    .lines()
                    .any(|line| line == *rule)
            );
        }
        assert_eq!(
            result.startup.root,
            PathBuf::from(crate::repository::LOCAL_STARTUP_ROOT)
        );
        assert!(
            !target
                .path()
                .join(crate::internal_runtime::REPOSITORY_RELATIVE_ROOT)
                .exists()
        );
        let project = fs::read_to_string(target.path().join(PROJECT_CONFIG_PATH)).unwrap();
        assert!(project.contains("version: 18"));
        assert!(project.contains("dockerfile: .traffic-e2e/Dockerfile.target"));
        assert!(project.contains("success_status: 200"));
        assert!(!project.contains("http_host:"));
        assert!(!project.contains("motan_port:"));
        assert!(project.contains("runtime_root: local/runtime"));
        assert!(project.contains("startup:"));
        assert!(!project.contains("breeze:"));
        assert!(project.contains("pr_base: dev-migration"));
        assert!(!project.contains("max_response_bytes"));
        assert!(!project.contains("protocol_detection:"));
        let dev_migration = Command::new("git")
            .arg("-C")
            .arg(target.path())
            .args(["rev-parse", "dev-migration^{commit}"])
            .output()
            .unwrap();
        let initialization_head = Command::new("git")
            .arg("-C")
            .arg(target.path())
            .args(["rev-parse", "initialization-work^{commit}"])
            .output()
            .unwrap();
        assert!(dev_migration.status.success());
        assert_eq!(dev_migration.stdout, initialization_head.stdout);
        assert_eq!(
            String::from_utf8(
                Command::new("git")
                    .arg("-C")
                    .arg(target.path())
                    .args(["branch", "--show-current"])
                    .output()
                    .unwrap()
                    .stdout
            )
            .unwrap()
            .trim(),
            "initialization-work"
        );
        let recorder =
            crate::config::AppConfig::load(target.path().join(PROJECT_CONFIG_PATH)).unwrap();
        assert_eq!(recorder.http_gateway.listen.to_string(), "0.0.0.0:4080");
        assert_eq!(
            recorder.http_gateway.matched_upstream,
            "http://127.0.0.1:8181"
        );
        assert_eq!(recorder.recording.max_body_bytes, DEFAULT_BODY_LIMIT_BYTES);
        crate::replay::validate_replay_policy(&target.path().join(VERIFICATION_POLICY_PATH))
            .unwrap();

        let error = initialize_repository_config_with(
            RepositoryConfigInitOptions {
                target_root: target.path().to_path_buf(),
                source: source_options(),
                http_backend_port: 8_181,
                http_gateway_port: 4_080,
                readiness_path: "/healthz".to_string(),
                upstream_dns: "10.10.10.11:53".parse().unwrap(),
                env_file: None,
            },
            capture_source,
            capture,
        )
        .unwrap_err();
        assert!(error.to_string().contains("refusing to initialize any"));
    }

    #[test]
    fn target_delivery_preserves_existing_dockerfiles() {
        let target = tempdir().unwrap();
        let dockerfile = target.path().join(TARGET_DOCKERFILE_PATH);
        let source_dockerfile = target.path().join(SOURCE_DOCKERFILE_PATH);
        fs::create_dir_all(dockerfile.parent().unwrap()).unwrap();
        fs::write(&dockerfile, "FROM existing\n").unwrap();
        fs::write(&source_dockerfile, "FROM existing-source\n").unwrap();
        let files = render_missing_target_delivery(
            target.path(),
            &RepositoryConfigInitOptions {
                target_root: target.path().to_path_buf(),
                source: source_options(),
                http_backend_port: 8_181,
                http_gateway_port: 4_080,
                readiness_path: "/ready".to_string(),
                upstream_dns: "10.10.10.11:53".parse().unwrap(),
                env_file: None,
            },
        )
        .unwrap();

        assert_eq!(fs::read_to_string(&dockerfile).unwrap(), "FROM existing\n");
        assert_eq!(
            fs::read_to_string(&source_dockerfile).unwrap(),
            "FROM existing-source\n"
        );
        assert_eq!(files.len(), 4);
        assert!(files.iter().all(|(path, _)| path != &dockerfile));
        assert!(files.iter().all(|(path, _)| path != &source_dockerfile));
        let main = files
            .iter()
            .find(|(path, _)| path.ends_with(TARGET_MAIN_PATH))
            .map(|(_, contents)| String::from_utf8_lossy(contents))
            .unwrap();
        assert!(!main.contains("TARGET_PORT_ENV"));
        assert!(main.contains("const DEFAULT_PORT: u16 = 8181;"));
        assert!(main.contains("#[http_server::get(\"/ready\", group = readiness_apis)]"));
        assert!(main.contains("StatusCode::OK"));
    }

    #[test]
    fn target_delivery_refuses_a_partial_existing_cargo_target() {
        let target = tempdir().unwrap();
        fs::write(
            target.path().join(TARGET_CARGO_PATH),
            "[package]\nname='partial'\n",
        )
        .unwrap();
        let error = render_missing_target_delivery(
            target.path(),
            &RepositoryConfigInitOptions {
                target_root: target.path().to_path_buf(),
                source: source_options(),
                http_backend_port: 8_080,
                http_gateway_port: 4_080,
                readiness_path: "/healthz".to_string(),
                upstream_dns: "10.10.10.11:53".parse().unwrap(),
                env_file: None,
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("either all exist or all be absent")
        );
    }

    #[test]
    fn ignore_generation_preserves_existing_rules_and_is_idempotent() {
        let target = tempdir().unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .arg(target.path())
                .status()
                .unwrap()
                .success()
        );
        fs::write(target.path().join(TARGET_GITIGNORE_PATH), "/vendor/\n").unwrap();
        fs::write(target.path().join(TARGET_DOCKERIGNORE_PATH), "/fixtures/\n").unwrap();

        let (_, git_updated, git_created) = ensure_target_gitignore(target.path()).unwrap();
        let (_, docker_updated, docker_created) =
            ensure_target_dockerignore(target.path()).unwrap();
        assert!(git_updated);
        assert!(!git_created);
        assert!(docker_updated);
        assert!(!docker_created);

        let gitignore = fs::read_to_string(target.path().join(TARGET_GITIGNORE_PATH)).unwrap();
        let dockerignore =
            fs::read_to_string(target.path().join(TARGET_DOCKERIGNORE_PATH)).unwrap();
        assert!(gitignore.starts_with("/vendor/\n"));
        assert!(dockerignore.starts_with("/fixtures/\n"));
        for rule in TARGET_GITIGNORE_RULES {
            assert_eq!(gitignore.lines().filter(|line| *line == *rule).count(), 1);
        }
        for rule in TARGET_DOCKERIGNORE_RULES {
            assert_eq!(
                dockerignore.lines().filter(|line| *line == *rule).count(),
                1
            );
        }

        assert!(!ensure_target_gitignore(target.path()).unwrap().1);
        assert!(!ensure_target_dockerignore(target.path()).unwrap().1);
    }
}
