//! Private AES inputs, including an explicitly proven default in frozen Source.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::policy::native::{EncryptionKey, SourceDefaultKey, StartupKey};

/// Neither Debug nor Serialize: only input file digests may leave this owner.
pub(crate) struct EncryptionKeySnapshot {
    root: PathBuf,
    source: StartupKey,
    value: Vec<u8>,
    source_revision: Option<(String, String)>,
    witnesses: Vec<(PathBuf, String)>,
}

impl EncryptionKeySnapshot {
    pub(crate) fn resolve(root: &Path, key: &EncryptionKey) -> Result<Self> {
        let (source, fallback) = match key {
            EncryptionKey::Startup { source } => (source, None),
            EncryptionKey::StartupOrSourceDefault { source, fallback } => (source, Some(fallback)),
        };
        let mut witnesses = Vec::new();
        let (value, source_revision) = match startup_value(root, source, &mut witnesses)? {
            Some(value) => (decode_key(&value)?, None),
            None => {
                let fallback =
                    fallback.context("AES key is absent from the selected startup input")?;
                let snapshot = crate::source_snapshot::load(root)?;
                let value = source_default(
                    root,
                    fallback,
                    snapshot.runtime.working_directory.as_deref(),
                )?;
                for path in ["manifest.json", "runtime.json"] {
                    add_witness(
                        &mut witnesses,
                        root.join(crate::repository::LOCAL_SOURCE_ROOT).join(path),
                    )?;
                }
                (
                    value,
                    Some((
                        snapshot.manifest.image.local_id,
                        snapshot.manifest.content_revision,
                    )),
                )
            }
        };
        Ok(Self {
            root: root.into(),
            source: source.clone(),
            value,
            source_revision,
            witnesses,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.value
    }

    pub(crate) fn witnesses(&self) -> impl Iterator<Item = &(PathBuf, String)> {
        self.witnesses.iter()
    }

    pub(crate) fn ensure_current(&self) -> Result<()> {
        let current = startup_value(&self.root, &self.source, &mut Vec::new())?;
        match &self.source_revision {
            None => ensure!(
                current.as_deref().map(decode_key).transpose()?.as_ref() == Some(&self.value),
                "AES startup input changed; obtain fresh evidence and plan again"
            ),
            Some((image, revision)) => {
                ensure!(
                    current.is_none(),
                    "AES startup input now overrides the proven Source default; plan again"
                );
                let snapshot = crate::source_snapshot::load(&self.root)?;
                ensure!(
                    &snapshot.manifest.image.local_id == image
                        && &snapshot.manifest.content_revision == revision,
                    "AES Source snapshot changed; obtain fresh evidence and plan again"
                );
            }
        }
        for (path, hash) in &self.witnesses {
            ensure!(
                format!("sha256:{:x}", Sha256::digest(bounded_read(path)?)) == *hash,
                "AES input evidence changed; obtain fresh evidence and plan again"
            );
        }
        Ok(())
    }
}

fn startup_value(
    root: &Path,
    source: &StartupKey,
    witnesses: &mut Vec<(PathBuf, String)>,
) -> Result<Option<String>> {
    match source {
        StartupKey::TargetEnv { name } => {
            crate::source_snapshot::validate_environment_name(name)?;
            let value = crate::startup::startup_environment_value(root, name)
                .map_err(|_| anyhow::anyhow!("cannot resolve AES startup environment"))?;
            for relative in [
                crate::repository::LOCAL_TARGET_ENV_PATH,
                crate::repository::LOCAL_SOURCE_MANIFEST_PATH,
                ".traffic-e2e/local/source/runtime.json",
            ] {
                let path = root.join(relative);
                if path.exists() {
                    add_witness(witnesses, path)?;
                }
            }
            Ok(value)
        }
        StartupKey::TargetFile { path, field } => {
            let path = Path::new(path);
            crate::startup::validate_mount_path(path)?;
            crate::source_snapshot::validate_environment_name(field)?;
            let (_, config) = crate::e2e_run::resolve_project(root)?;
            let snapshot = crate::startup::load_startup_snapshot(root, &config.target_startup)?;
            ensure!(
                snapshot
                    .mounts()
                    .iter()
                    .any(|mount| !mount.writable && path.starts_with(&mount.path)),
                "AES key file requires a declared read-only startup mount"
            );
            let host = crate::startup::startup_mount_source(root, path)?;
            let bytes = bounded_read(&host)?;
            let mut found = None;
            for entry in dotenvy::Iter::new(bytes.as_slice()) {
                let (name, value) =
                    entry.map_err(|_| anyhow::anyhow!("invalid AES startup key file"))?;
                if name == *field {
                    ensure!(found.is_none(), "duplicate AES key field in startup file");
                    found = Some(value);
                }
            }
            witnesses.push((host, format!("sha256:{:x}", Sha256::digest(&bytes))));
            add_witness(
                witnesses,
                root.join(crate::repository::LOCAL_STARTUP_MANIFEST_PATH),
            )?;
            Ok(found)
        }
    }
}

fn decode_key(value: &str) -> Result<Vec<u8>> {
    let bytes = if let Some(encoded) = value.strip_prefix("base64:") {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("AES key has invalid base64 encoding"))?
    } else {
        value.as_bytes().to_vec()
    };
    ensure!(
        matches!(bytes.len(), 16 | 24 | 32),
        "AES key must contain exactly 16, 24 or 32 bytes"
    );
    Ok(bytes)
}

fn source_default(
    root: &Path,
    fallback: &SourceDefaultKey,
    working_directory: Option<&str>,
) -> Result<Vec<u8>> {
    let relative = Path::new(&fallback.path);
    ensure!(
        !fallback.path.is_empty()
            && relative.is_relative()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "AES Source default requires an exact relative file"
    );
    let base = Path::new(working_directory.unwrap_or("/"));
    ensure!(
        base.is_absolute()
            && base
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "Source working directory is invalid"
    );
    let local = root.join(crate::repository::LOCAL_ROOT);
    ensure!(
        fs::symlink_metadata(&local)?.is_dir(),
        "local evidence root must be a real directory"
    );
    let staging = local.join(format!(".aes-source-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
    let result = (|| {
        let path = staging.join("source");
        ensure!(
            !crate::source_snapshot::copy_path(root, &base.join(relative), &path)?,
            "AES Source default cannot come from a writable mount"
        );
        let bytes = bounded_read(&path)?;
        source_literal(&bytes, fallback)
    })();
    let cleanup = fs::remove_dir_all(&staging);
    let value = result?;
    cleanup.context("failed to remove private AES Source extraction")?;
    Ok(value)
}

fn source_literal(bytes: &[u8], fallback: &SourceDefaultKey) -> Result<Vec<u8>> {
    ensure!(
        format!("sha256:{:x}", Sha256::digest(bytes)) == fallback.file_sha256,
        "AES Source file differs from the proven fingerprint"
    );
    let [start, end] = fallback.byte_range;
    ensure!(
        start < end && end - start <= 256 && end <= bytes.len() as u64,
        "AES Source literal range is invalid"
    );
    let literal = std::str::from_utf8(&bytes[start as usize..end as usize])
        .context("AES Source literal must be UTF-8")?;
    decode_key(literal)
}

fn bounded_read(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 4 * 1024 * 1024,
        "AES evidence requires a bounded regular file"
    );
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "AES evidence file exceeds bounds"
    );
    Ok(bytes)
}

fn add_witness(witnesses: &mut Vec<(PathBuf, String)>, path: PathBuf) -> Result<()> {
    let hash = format!("sha256:{:x}", Sha256::digest(bounded_read(&path)?));
    if !witnesses.iter().any(|(existing, _)| existing == &path) {
        witnesses.push((path, hash));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_keys_use_explicit_encoding_and_exact_frozen_literal() {
        let key = "0123456789abcdef";
        assert_eq!(decode_key(key).unwrap(), key.as_bytes());
        assert_eq!(
            decode_key("base64:MDEyMzQ1Njc4OWFiY2RlZg==").unwrap(),
            key.as_bytes()
        );
        assert!(decode_key("base64:bad!").is_err());
        assert!(decode_key("short").is_err());
        let bytes = format!("default = '{key}'\n").into_bytes();
        let mut fallback = SourceDefaultKey {
            path: "source.py".into(),
            file_sha256: format!("sha256:{:x}", Sha256::digest(&bytes)),
            byte_range: [11, 27],
        };
        assert_eq!(source_literal(&bytes, &fallback).unwrap(), key.as_bytes());
        fallback.byte_range = [11, 26];
        assert!(source_literal(&bytes, &fallback).is_err());
        fallback.file_sha256 = "sha256:wrong".into();
        assert!(source_literal(&bytes, &fallback).is_err());
    }
}
