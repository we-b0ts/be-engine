use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ARCHIVE_NAME: &str = "image.tar";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceImage {
    pub reference: String,
    pub registry_digest: Option<String>,
    pub local_id: String,
    pub architecture: String,
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_sha256: Option<String>,
}

pub(super) fn is_image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_digest)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl SourceImage {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            is_image_id(&self.local_id)
                && self.os == "linux"
                && self.architecture == "amd64"
                && (self.registry_digest.is_some() || self.archive_sha256.is_some())
                && self.registry_digest.as_ref().is_none_or(|value| {
                    value
                        .rsplit_once("@sha256:")
                        .is_some_and(|(name, digest)| !name.is_empty() && is_digest(digest))
                })
                && self.archive_sha256.as_deref().is_none_or(is_digest),
            "source snapshot image identity is invalid"
        );
        Ok(())
    }
}

pub(super) fn save_archive(image_id: &str, root: &Path) -> Result<String> {
    let path = root.join(ARCHIVE_NAME);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    let output = Command::new("docker")
        .args(["image", "save", image_id])
        .stdin(Stdio::null())
        .stdout(file)
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to save source container image")?
        .wait_with_output()?;
    ensure!(
        output.status.success(),
        "failed to save source container image: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    File::open(&path)?.sync_all()?;
    archive_digest(&path)
}

pub(super) fn remove_captured_image(image_id: &str) {
    let _ = Command::new("docker")
        .args(["image", "rm", image_id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn archive_digest(path: &Path) -> Result<String> {
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "source image archive must be a regular file"
    );
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub(super) fn ensure_local_image(image: &SourceImage, root: &Path) -> Result<()> {
    let inspect = || {
        Command::new("docker")
            .args(["image", "inspect", "--format", "{{.Id}}", &image.local_id])
            .stdin(Stdio::null())
            .output()
            .context("failed to inspect snapshotted source image")
    };
    let mut output = inspect()?;
    if !output.status.success() {
        let restored = if let Some(digest) = &image.archive_sha256 {
            let archive = root.join(ARCHIVE_NAME);
            ensure!(
                &archive_digest(&archive)? == digest,
                "source image archive content changed"
            );
            Command::new("docker")
                .args(["image", "load", "--input"])
                .arg(archive)
                .stdin(Stdio::null())
                .output()
                .context("failed to restore archived source image")?
        } else {
            let digest = image
                .registry_digest
                .as_deref()
                .context("source image has no recovery source")?;
            Command::new("docker")
                .args(["pull", "--platform", "linux/amd64", digest])
                .stdin(Stdio::null())
                .output()
                .context("failed to restore snapshotted source image")?
        };
        ensure!(
            restored.status.success(),
            "failed to restore snapshotted source image {}: {}",
            image.local_id,
            String::from_utf8_lossy(&restored.stderr).trim()
        );
        output = inspect()?;
    }
    ensure!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == image.local_id,
        "snapshotted source image {} does not resolve to its initialization image ID",
        image.local_id
    );
    Ok(())
}

pub(super) fn copy_image_path(
    image: &SourceImage,
    root: &Path,
    path: &Path,
    destination: &Path,
) -> Result<()> {
    ensure_local_image(image, root)?;
    let name = format!("traffic-e2e-source-copy-{}", Uuid::new_v4().simple());
    let create = Command::new("docker")
        .args(["create", "--name", &name, &image.local_id])
        .stdin(Stdio::null())
        .output()
        .context("failed to create source image copy container")?;
    ensure!(
        create.status.success(),
        "failed to create source image copy container: {}",
        String::from_utf8_lossy(&create.stderr).trim()
    );
    let result = (|| -> Result<()> {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let source = format!("{name}:{}", path.display());
        let output = Command::new("docker")
            .args(["cp", "--archive", "--follow-link", &source])
            .arg(destination)
            .stdin(Stdio::null())
            .output()
            .with_context(|| {
                format!("failed to copy image-local source path {}", path.display())
            })?;
        ensure!(
            output.status.success(),
            "failed to copy image-local source path {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    })();
    let cleanup = Command::new("docker")
        .args(["rm", "--volumes", &name])
        .stdin(Stdio::null())
        .output()
        .context("failed to remove source image copy container");
    result?;
    let cleanup = cleanup?;
    ensure!(
        cleanup.status.success(),
        "failed to remove source image copy container"
    );
    Ok(())
}
