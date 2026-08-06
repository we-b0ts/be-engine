use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use tokio::process::Command;
use uuid::Uuid;

use super::TARGET_USER;
use super::model::{TargetContainerConfig, TargetImage};

const BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImageInspection {
    id: String,
    architecture: String,
    os: String,
    config: ImageConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImageConfig {
    user: String,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    env: Option<Vec<String>>,
}

pub(crate) fn image_tag(target_root: &Path) -> Result<String> {
    let name = crate::repository::directory_name(target_root)?;
    let mut normalized = String::with_capacity(name.len());
    let mut previous_separator = false;
    for character in name.chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            normalized.push(character);
            previous_separator = matches!(character, '.' | '_' | '-');
        } else if !previous_separator {
            normalized.push('-');
            previous_separator = true;
        }
    }
    let normalized = normalized.trim_matches(|character| matches!(character, '.' | '_' | '-'));
    ensure!(
        !normalized.is_empty(),
        "target repository name cannot form a Docker image tag"
    );
    Ok(format!("traffic-e2e/{normalized}-target:cache"))
}

pub(crate) async fn build_image(config: &TargetContainerConfig) -> Result<TargetImage> {
    validate_build_contract(config)?;
    let tag = image_tag(&config.target_root)?;
    let control_root =
        crate::internal_runtime::root(&config.target_root).join("target-container/build");
    tokio::fs::create_dir_all(&control_root)
        .await
        .with_context(|| format!("failed to create {}", control_root.display()))?;
    let iid_path = control_root.join(format!("{}.iid", Uuid::new_v4()));

    let mut command = Command::new("docker");
    command
        .arg("build")
        .args(["--platform", "linux/amd64", "--network", "host"])
        .args(["--build-arg", "HTTP_PROXY"])
        .args(["--build-arg", "HTTPS_PROXY"])
        .args(["--build-arg", "ALL_PROXY"])
        .args(["--build-arg", "NO_PROXY"])
        .arg("--iidfile")
        .arg(&iid_path)
        .arg("--tag")
        .arg(&tag)
        .arg("--file")
        .arg(&config.dockerfile)
        .arg(&config.target_root)
        .current_dir(&config.target_root)
        .env("DOCKER_BUILDKIT", "1")
        .env_remove(crate::request_headers::ENCRYPTION_KEY_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .context("failed to start target image build")?;
    let status = match tokio::time::timeout(BUILD_TIMEOUT, child.wait()).await {
        Ok(status) => status.context("failed to wait for target image build")?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = tokio::fs::remove_file(&iid_path).await;
            bail!("target image build exceeded the 1800 second limit");
        }
    };
    if !status.success() {
        let _ = tokio::fs::remove_file(&iid_path).await;
        bail!("target image build exited with {status}");
    }

    let iid = tokio::fs::read_to_string(&iid_path)
        .await
        .with_context(|| format!("target image build did not write {}", iid_path.display()))?;
    let _ = tokio::fs::remove_file(&iid_path).await;
    let iid = iid.trim().to_string();
    validate_image_id(&iid)?;
    let inspection = inspect_image(&tag).await?;
    ensure!(
        inspection.id == iid,
        "target image tag resolved to {} instead of build result {iid}",
        inspection.id
    );
    validate_image_contract(&inspection)?;
    Ok(TargetImage { tag, id: iid })
}

fn validate_build_contract(config: &TargetContainerConfig) -> Result<()> {
    require_regular_file(&config.dockerfile, "target Dockerfile")?;
    ensure!(
        config.dockerfile == config.target_root.join(super::TARGET_DOCKERFILE_RELATIVE),
        "target Dockerfile must be {}",
        super::TARGET_DOCKERFILE_RELATIVE
    );
    let dockerfile = std::fs::read_to_string(&config.dockerfile)
        .with_context(|| format!("failed to read {}", config.dockerfile.display()))?;
    validate_dockerfile_contract(config, &dockerfile)?;
    let dockerignore = config.target_root.join(".dockerignore");
    require_regular_file(&dockerignore, "target .dockerignore")?;
    let contents = std::fs::read_to_string(&dockerignore)
        .with_context(|| format!("failed to read {}", dockerignore.display()))?;
    for required in [".git", ".traffic-e2e/local", "target"] {
        ensure!(
            contents
                .lines()
                .any(|line| dockerignore_covers(line, required)),
            ".dockerignore must exclude {required}/ from the target build context"
        );
    }
    Ok(())
}

fn validate_dockerfile_contract(config: &TargetContainerConfig, dockerfile: &str) -> Result<()> {
    ensure!(
        dockerfile.contains(&format!("FROM {} AS builder", super::TARGET_BUILDER_IMAGE)),
        "target Dockerfile must use the pinned traffic-e2e Rust builder"
    );
    ensure!(
        dockerfile.contains(&format!("FROM {}", super::TARGET_RUNTIME_IMAGE)),
        "target Dockerfile must use the pinned traffic-e2e Rust runtime as its final stage"
    );
    ensure!(
        dockerfile
            .lines()
            .filter(|line| line.trim_start().starts_with("FROM "))
            .count()
            >= 2,
        "target Dockerfile must be a multi-stage build"
    );
    for required in [
        "id=traffic-e2e-cargo-registry,target=/opt/rust/cargo/registry,sharing=locked",
        "id=traffic-e2e-cargo-git,target=/opt/rust/cargo/git,sharing=locked",
        "cargo build --locked --release",
    ] {
        ensure!(
            dockerfile.contains(required),
            "target Dockerfile is missing required build contract {required:?}"
        );
    }
    let tag = image_tag(&config.target_root)?;
    let project = tag
        .strip_prefix("traffic-e2e/")
        .and_then(|value| value.strip_suffix("-target:cache"))
        .context("failed to derive target cache identity")?;
    let target_cache =
        format!("id=traffic-e2e-{project}-target,target=/build/target,sharing=locked");
    ensure!(
        dockerfile.contains(&target_cache),
        "target Dockerfile must use project-specific BuildKit target cache {target_cache:?}"
    );
    Ok(())
}

fn dockerignore_covers(line: &str, required: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return false;
    }
    let normalized = line
        .trim_start_matches('/')
        .trim_end_matches('/')
        .trim_end_matches("/**");
    normalized == required
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

async fn inspect_image(reference: &str) -> Result<ImageInspection> {
    let output = tokio::time::timeout(
        DOCKER_TIMEOUT,
        Command::new("docker")
            .args(["image", "inspect", reference])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .context("timed out while inspecting target image")??;
    ensure!(
        output.status.success(),
        "failed to inspect target image: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let mut values: Vec<ImageInspection> =
        serde_json::from_slice(&output.stdout).context("Docker returned invalid image JSON")?;
    ensure!(
        values.len() == 1,
        "Docker returned {} target image inspections",
        values.len()
    );
    Ok(values.remove(0))
}

fn validate_image_contract(inspection: &ImageInspection) -> Result<()> {
    validate_image_id(&inspection.id)?;
    ensure!(
        inspection.os == "linux" && inspection.architecture == "amd64",
        "target image must be linux/amd64, got {}/{}",
        inspection.os,
        inspection.architecture
    );
    ensure!(
        inspection.config.user == TARGET_USER,
        "target image must default to USER {TARGET_USER}, got {:?}",
        inspection.config.user
    );
    ensure!(
        inspection
            .config
            .entrypoint
            .as_ref()
            .is_some_and(|entrypoint| !entrypoint.is_empty()),
        "target image must declare a non-empty OCI entrypoint"
    );
    ensure!(
        inspection
            .config
            .cmd
            .as_ref()
            .is_none_or(|command| command.is_empty()),
        "target image must not declare default OCI command arguments"
    );
    for value in inspection.config.env.iter().flatten() {
        let name = value
            .split_once('=')
            .map_or(value.as_str(), |(name, _)| name);
        ensure!(
            !matches!(
                name.to_ascii_uppercase().as_str(),
                "HTTP_PROXY"
                    | "HTTPS_PROXY"
                    | "ALL_PROXY"
                    | "NO_PROXY"
                    | crate::request_headers::ENCRYPTION_KEY_ENV
            ),
            "target image must not persist environment variable {name}"
        );
    }
    Ok(())
}

pub(super) fn validate_image_id(image_id: &str) -> Result<()> {
    ensure!(
        image_id.len() == 71
            && image_id.starts_with("sha256:")
            && image_id[7..].bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid immutable target image ID {image_id:?}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_tags_are_lowercase_and_bounded() {
        assert_eq!(
            image_tag(Path::new("/tmp/Service Graph@RS")).unwrap(),
            "traffic-e2e/service-graph-rs-target:cache"
        );
    }

    #[test]
    fn dockerignore_contract_accepts_root_scoped_directories() {
        assert!(dockerignore_covers(
            "/.traffic-e2e/local/",
            ".traffic-e2e/local"
        ));
        assert!(dockerignore_covers("target/**", "target"));
        assert!(!dockerignore_covers("!target/", "target"));
        assert!(!dockerignore_covers("other-target/", "target"));
    }

    #[test]
    fn image_ids_must_be_full_sha256_values() {
        validate_image_id(&format!("sha256:{}", "a".repeat(64))).unwrap();
        assert!(validate_image_id("sha256:abc").is_err());
    }

    #[test]
    fn dockerfile_contract_requires_pinned_images_and_stable_caches() {
        let config = TargetContainerConfig {
            target_root: Path::new("/tmp/service").to_path_buf(),
            dockerfile: Path::new("/tmp/service/.traffic-e2e/Dockerfile.e2e").to_path_buf(),
            boot_dir: Path::new("/tmp/service/.traffic-e2e/local/boot").to_path_buf(),
            port: 8081,
            readiness_path: "/healthz".to_string(),
            readiness_status: 200,
            startup_timeout: Duration::from_secs(60),
            breeze_enabled: false,
        };
        let dockerfile = format!(
            "FROM {} AS builder\nRUN --mount=type=cache,id=traffic-e2e-cargo-registry,target=/opt/rust/cargo/registry,sharing=locked --mount=type=cache,id=traffic-e2e-cargo-git,target=/opt/rust/cargo/git,sharing=locked --mount=type=cache,id=traffic-e2e-service-target,target=/build/target,sharing=locked cargo build --locked --release\nFROM {}\nENTRYPOINT [\"/app/bin/service\"]\n",
            super::super::TARGET_BUILDER_IMAGE,
            super::super::TARGET_RUNTIME_IMAGE,
        );

        validate_dockerfile_contract(&config, &dockerfile).unwrap();
    }
}
