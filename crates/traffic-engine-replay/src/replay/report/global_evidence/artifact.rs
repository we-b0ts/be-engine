//! Atomic, checksummed shared artifacts with fixed project or report-relative anchors.
use crate::dependency_index::store;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
const MANIFEST: &str = "manifest.json";
fn report_parent(report: &Path) -> Result<&Path> {
    let parent = report.parent().context("report has no parent")?;
    Ok(if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    })
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Anchor {
    Project { root: PathBuf },
    ReportDirectory,
}
impl Anchor {
    fn for_report(report: &Path) -> Result<Self> {
        let parent = fs::canonicalize(report_parent(report)?)?;
        Ok(
            match parent
                .ancestors()
                .find(|p| p.file_name().is_some_and(|n| n == ".traffic-e2e"))
            {
                Some(root) => Self::Project {
                    root: root.to_owned(),
                },
                None => Self::ReportDirectory,
            },
        )
    }
    fn root(&self, report: &Path, create: bool) -> Result<PathBuf> {
        let (root, parts): (PathBuf, &[&str]) = match self {
            Self::Project { root } => {
                ensure!(
                    root.is_absolute() && root.file_name().is_some_and(|n| n == ".traffic-e2e"),
                    "invalid shared inventory project anchor"
                );
                ensure!(
                    fs::canonicalize(root)? == *root,
                    "linked shared inventory project anchor"
                );
                (
                    root.clone(),
                    &["local", "artifacts", "shared-global-inventories"],
                )
            }
            Self::ReportDirectory => (
                fs::canonicalize(report_parent(report)?)?,
                &[".replay", "shared-global-inventories"],
            ),
        };
        let mut path = root;
        for part in parts {
            path.push(part);
            if create {
                store::private_directory(&path)?;
            }
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "linked shared inventory directory"
            );
        }
        Ok(path)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    anchor: Anchor,
    key: String,
    sha256: String,
}
pub fn digest(value: &impl Serialize) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
impl ArtifactReference {
    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn existing<T: Serialize + DeserializeOwned>(
        report: &Path,
        key: &str,
    ) -> Result<Option<Self>> {
        ensure!(valid_digest(key), "invalid shared inventory key");
        let parent = report_parent(report)?;
        if !parent.exists() {
            store::private_directory(parent)?;
        }
        let anchor = Anchor::for_report(report)?;
        let root = anchor.root(report, true)?;
        let manifest = root.join(key).join(MANIFEST);
        if !manifest.try_exists()? {
            return Ok(None);
        }
        let document: T = store::read_json(&manifest)?;
        Ok(Some(Self {
            anchor,
            key: key.into(),
            sha256: digest(&document)?,
        }))
    }
    /// Domain owners bind all source, projection-version and policy/layout inputs
    /// in the key, then validate that binding after loading the document.
    pub fn retain<T: Serialize + DeserializeOwned>(
        report: &Path,
        key: String,
        build: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<Self> {
        ensure!(valid_digest(&key), "invalid shared inventory key");
        let parent = report_parent(report)?;
        if !parent.exists() {
            store::private_directory(parent)?;
        }
        let anchor = Anchor::for_report(report)?;
        Self::retain_at(report, key, anchor, build)
    }
    pub fn retain_portable<T: Serialize + DeserializeOwned>(
        report: &Path,
        key: String,
        build: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<Self> {
        ensure!(valid_digest(&key), "invalid shared inventory key");
        Self::retain_at(report, key, Anchor::ReportDirectory, build)
    }
    fn retain_at<T: Serialize + DeserializeOwned>(
        report: &Path,
        key: String,
        anchor: Anchor,
        build: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<Self> {
        let root = anchor.root(report, true)?;
        let sha256 = publish(&root, &key, None, build)?;
        Ok(Self {
            anchor,
            key,
            sha256,
        })
    }
    pub fn load<T: Serialize + DeserializeOwned>(&self, report: &Path) -> Result<(T, PathBuf)> {
        ensure!(
            valid_digest(&self.key) && valid_digest(&self.sha256),
            "invalid shared inventory digest"
        );
        let directory = self.anchor.root(report, false)?.join(&self.key);
        let metadata = fs::symlink_metadata(&directory)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "linked shared inventory"
        );
        let document: T = store::read_json(&directory.join(MANIFEST))?;
        ensure!(
            digest(&document)? == self.sha256,
            "shared inventory manifest changed"
        );
        Ok((document, directory))
    }
    /// Same-owner publication reads only the small document. Cross-root exports
    /// retain immutable pages once and explicitly rebind the anchor.
    pub fn stage<T: Serialize + DeserializeOwned>(
        &self,
        source: &Path,
        destination: &Path,
        build: impl FnOnce(&T, &Path, &Path) -> Result<T>,
    ) -> Result<Self> {
        let (document, source_root) = self.load::<T>(source)?;
        let parent = report_parent(destination)?;
        if !parent.exists() {
            store::private_directory(parent)?;
        }
        let anchor = Anchor::for_report(destination)?;
        let root = anchor.root(destination, true)?;
        if root == self.anchor.root(source, false)? {
            return Ok(self.clone());
        }
        publish(&root, &self.key, Some(&self.sha256), |staging| {
            build(&document, &source_root, staging)
        })?;
        Ok(Self {
            anchor,
            ..self.clone()
        })
    }
}
struct PublicationLock(File);
impl Drop for PublicationLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn publish<T: Serialize + DeserializeOwned>(
    root: &Path,
    key: &str,
    expected: Option<&str>,
    build: impl FnOnce(&Path) -> Result<T>,
) -> Result<String> {
    use std::os::unix::fs::OpenOptionsExt;
    let destination = root.join(key);
    let existing = || -> Result<Option<String>> {
        if !destination.exists() {
            return Ok(None);
        }
        let metadata = fs::symlink_metadata(&destination)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "linked shared inventory"
        );
        let document: T = store::read_json(&destination.join(MANIFEST))?;
        let sha256 = digest(&document)?;
        ensure!(
            expected.is_none_or(|value| value == sha256),
            "shared inventory publication collision"
        );
        Ok(Some(sha256))
    };
    if let Some(sha256) = existing()? {
        return Ok(sha256);
    }
    let lock_path = root.join(format!(".{key}.lock"));
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(lock_path)?;
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0,
        "failed to lock shared inventory: {}",
        std::io::Error::last_os_error()
    );
    let _lock = PublicationLock(file);
    if let Some(sha256) = existing()? {
        return Ok(sha256);
    }
    let staging = root.join(format!(".{key}-{}.staging", uuid::Uuid::new_v4().simple()));
    let result = (|| -> Result<String> {
        store::private_directory(&staging)?;
        let document = build(&staging)?;
        let sha256 = digest(&document)?;
        ensure!(
            expected.is_none_or(|value| value == sha256),
            "shared inventory changed during export"
        );
        store::write_json(&staging.join(MANIFEST), &document)?;
        File::open(&staging)?.sync_all()?;
        fs::rename(&staging, destination)?;
        File::open(root)?.sync_all()?;
        Ok(sha256)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(staging);
    }
    result
}

#[cfg(test)]
mod tests;
