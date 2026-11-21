use std::ffi::OsString;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::process::Command;
use uuid::Uuid;

use super::TARGET_USER;
use super::model::{TargetContainerConfig, TargetImage};

const BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BUILD_STREAM_TAIL_BYTES: usize = 16 * 1024;
const MAX_BUILD_DIAGNOSTIC_CHARS: usize = 1_536;

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
    let uses_ssh_forwarding = validate_build_contract(config)?;
    let ssh_agent = uses_ssh_forwarding
        .then(|| super::ssh_agent::ManagedSshAgent::prepare(&config.target_root))
        .transpose()?;
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
        .args(["--build-arg", "NO_PROXY"]);
    for context in &config.build_contexts {
        command
            .arg("--build-context")
            .arg(build_context_argument(context));
    }
    if let Some(ssh_agent) = ssh_agent {
        ssh_agent.apply_to(&mut command);
    }
    command
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .context("failed to start target image build")?;
    let stdout = child
        .stdout
        .take()
        .context("target image build stdout was not captured")?;
    let stderr = child
        .stderr
        .take()
        .context("target image build stderr was not captured")?;
    let stdout_task = tokio::spawn(tee_bounded_tail(stdout, tokio::io::stdout()));
    let stderr_task = tokio::spawn(tee_bounded_tail(stderr, tokio::io::stderr()));
    let status = match tokio::time::timeout(BUILD_TIMEOUT, child.wait()).await {
        Ok(status) => Some(status.context("failed to wait for target image build")?),
        Err(_) => {
            let _ = child.kill().await;
            None
        }
    };
    let stdout_tail = stdout_task
        .await
        .context("target image build stdout capture task failed")?
        .context("failed to read target image build stdout")?;
    let stderr_tail = stderr_task
        .await
        .context("target image build stderr capture task failed")?
        .context("failed to read target image build stderr")?;
    let diagnostic = build_failure_diagnostic(&stdout_tail, &stderr_tail);
    let Some(status) = status else {
        let _ = tokio::fs::remove_file(&iid_path).await;
        bail!("target image build exceeded the 1800 second limit; {diagnostic}");
    };
    if !status.success() {
        let _ = tokio::fs::remove_file(&iid_path).await;
        bail!("target image build exited with {status}; {diagnostic}");
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

fn build_context_argument(context: &crate::e2e_run::TargetBuildContext) -> OsString {
    let mut argument = OsString::from(&context.name);
    argument.push("=");
    argument.push(&context.root);
    argument
}

async fn tee_bounded_tail<R, W>(mut reader: R, mut writer: W) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut tail = Vec::new();
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        let _ = writer.write_all(chunk).await;
        append_bounded_tail(&mut tail, chunk);
    }
    let _ = writer.flush().await;
    Ok(tail)
}

fn append_bounded_tail(tail: &mut Vec<u8>, chunk: &[u8]) {
    if chunk.len() >= MAX_BUILD_STREAM_TAIL_BYTES {
        tail.clear();
        tail.extend_from_slice(&chunk[chunk.len() - MAX_BUILD_STREAM_TAIL_BYTES..]);
        return;
    }
    let excess = tail
        .len()
        .saturating_add(chunk.len())
        .saturating_sub(MAX_BUILD_STREAM_TAIL_BYTES);
    if excess > 0 {
        tail.drain(..excess);
    }
    tail.extend_from_slice(chunk);
}

fn build_failure_diagnostic(stdout: &[u8], stderr: &[u8]) -> String {
    let mut diagnostics = Vec::new();
    if let Some(summary) = stream_failure_summary("docker stderr", stderr) {
        diagnostics.push(summary);
    }
    if let Some(summary) = stream_failure_summary("docker stdout", stdout) {
        diagnostics.push(summary);
    }
    if diagnostics.is_empty() {
        return "no Docker build output was captured".to_string();
    }

    let mut diagnostic = diagnostics.join("; ");
    if diagnostic.chars().count() <= MAX_BUILD_DIAGNOSTIC_CHARS {
        return diagnostic;
    }
    let suffix = "… [build output truncated]";
    diagnostic = diagnostic
        .chars()
        .take(MAX_BUILD_DIAGNOSTIC_CHARS.saturating_sub(suffix.chars().count()))
        .collect();
    diagnostic.push_str(suffix);
    diagnostic
}

fn stream_failure_summary(label: &str, bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let lines = text
        .lines()
        .map(strip_terminal_control)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }
    let mut selected = lines
        .iter()
        .rev()
        .filter(|line| is_failure_line(line))
        .take(8)
        .cloned()
        .collect::<Vec<_>>();
    if selected.is_empty() {
        selected = lines.iter().rev().take(8).cloned().collect();
    }
    selected.reverse();
    Some(format!("{label}: {}", selected.join(" | ")))
}

fn is_failure_line(line: &str) -> bool {
    let line = line.to_ascii_lowercase();
    [
        "error",
        "failed",
        "fatal",
        "permission denied",
        "publickey",
        "ssh",
        "cargo",
        "could not",
        "unable to",
    ]
    .iter()
    .any(|needle| line.contains(needle))
}

fn strip_terminal_control(line: &str) -> String {
    let mut cleaned = String::with_capacity(line.len());
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' {
            if characters.next_if_eq(&'[').is_some() {
                for control in characters.by_ref() {
                    if ('@'..='~').contains(&control) {
                        break;
                    }
                }
            }
            continue;
        }
        if !character.is_control() || character == '\t' {
            cleaned.push(character);
        }
    }
    cleaned
}

fn validate_build_contract(config: &TargetContainerConfig) -> Result<bool> {
    require_regular_file(&config.dockerfile, "target Dockerfile")?;
    ensure!(
        config.dockerfile == config.target_root.join(super::TARGET_DOCKERFILE_RELATIVE),
        "target Dockerfile must be {}",
        super::TARGET_DOCKERFILE_RELATIVE
    );
    let dockerfile = std::fs::read_to_string(&config.dockerfile)
        .with_context(|| format!("failed to read {}", config.dockerfile.display()))?;
    validate_build_contexts(&dockerfile, &config.build_contexts)?;
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
    Ok(dockerfile_uses_ssh_forwarding(&dockerfile))
}

fn validate_build_contexts(
    dockerfile: &str,
    contexts: &[crate::e2e_run::TargetBuildContext],
) -> Result<()> {
    for context in contexts {
        ensure!(
            dockerfile_uses_build_context(dockerfile, &context.name),
            "target Dockerfile must consume managed build context {:?} with COPY --from, RUN --mount=from, or FROM",
            context.name
        );
    }
    Ok(())
}

fn dockerfile_uses_ssh_forwarding(dockerfile: &str) -> bool {
    dockerfile.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#') && line.contains("--mount=type=ssh")
    })
}

fn dockerfile_uses_build_context(dockerfile: &str, name: &str) -> bool {
    let copy_from = format!("--from={name}");
    let mount_from = format!("from={name}");
    dockerfile.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        let mut fields = line.split_ascii_whitespace();
        if fields.next() == Some("FROM") && fields.next() == Some(name) {
            return true;
        }
        line.split_ascii_whitespace().any(|field| {
            field == copy_from.as_str()
                || field.strip_prefix("--mount=").is_some_and(|mount| {
                    mount.split(',').any(|option| option == mount_from.as_str())
                })
        })
    })
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
    fn managed_build_accepts_a_single_stage_non_rust_dockerfile() {
        let root = tempfile::tempdir().unwrap();
        let dockerfile = root.path().join(super::super::TARGET_DOCKERFILE_RELATIVE);
        std::fs::create_dir_all(dockerfile.parent().unwrap()).unwrap();
        std::fs::write(
            root.path().join(".dockerignore"),
            ".git\n.traffic-e2e/local\ntarget\n",
        )
        .unwrap();
        let recipe = "FROM python:3.13-slim\nCOPY app.py /app.py\nUSER 998:998\nENTRYPOINT [\"python\", \"/app.py\"]\n";
        std::fs::write(&dockerfile, recipe).unwrap();
        let config = TargetContainerConfig {
            target_root: root.path().to_path_buf(),
            dockerfile,
            build_contexts: Vec::new(),
            startup: crate::startup::StartupConfig::default(),
            port: 8081,
        };
        assert!(!validate_build_contract(&config).unwrap());

        std::fs::write(
            &config.dockerfile,
            recipe.replace(
                "COPY app.py /app.py",
                "RUN --mount=type=ssh,required=true make\nCOPY app.py /app.py",
            ),
        )
        .unwrap();
        assert!(validate_build_contract(&config).unwrap());
    }

    #[test]
    fn dockerfile_contract_requires_declared_build_contexts_to_be_consumed() {
        let contexts = [crate::e2e_run::TargetBuildContext {
            name: "shared-source".into(),
            root: PathBuf::from("/tmp/shared"),
        }];

        assert!(
            validate_build_contexts("FROM debian:bookworm-slim", &contexts)
                .unwrap_err()
                .to_string()
                .contains("shared-source")
        );
        validate_build_contexts(
            "FROM debian:bookworm-slim\nCOPY --from=shared-source src /app",
            &contexts,
        )
        .unwrap();

        assert!(dockerfile_uses_build_context(
            "RUN --mount=type=bind,from=mounted-source,target=/src make",
            "mounted-source"
        ));
    }

    #[test]
    fn build_context_argument_preserves_name_and_path() {
        let context = crate::e2e_run::TargetBuildContext {
            name: "shared-source".to_string(),
            root: PathBuf::from("/tmp/repository/shared"),
        };

        assert_eq!(
            build_context_argument(&context),
            OsString::from("shared-source=/tmp/repository/shared")
        );
    }

    #[test]
    fn build_failure_diagnostic_prioritizes_actionable_lines() {
        let stdout =
            b"#1 compiling\n\x1b[31m#2 ERROR: failed to fetch git dependency\x1b[0m\n#3 canceled\n";
        let stderr = b"warning\nPermission denied (publickey)\nfatal: could not read repository\n";
        let diagnostic = build_failure_diagnostic(stdout, stderr);

        assert!(diagnostic.contains("Permission denied (publickey)"));
        assert!(diagnostic.contains("fatal: could not read repository"));
        assert!(diagnostic.contains("ERROR: failed to fetch git dependency"));
        assert!(!diagnostic.contains("[31m"));
        assert!(!diagnostic.contains("compiling"));
        assert!(!diagnostic.contains("canceled"));
    }

    #[test]
    fn build_stream_tail_is_bounded_to_latest_bytes() {
        let mut tail = b"old".to_vec();
        append_bounded_tail(&mut tail, &vec![b'x'; MAX_BUILD_STREAM_TAIL_BYTES + 4]);
        assert_eq!(tail.len(), MAX_BUILD_STREAM_TAIL_BYTES);
        assert!(tail.iter().all(|byte| *byte == b'x'));
    }
}
