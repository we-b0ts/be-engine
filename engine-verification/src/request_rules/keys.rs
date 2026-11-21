//! Signing-key sources. Values are resolved from target startup inputs, never
//! serialized into plans, policy, command arguments, or diagnostics.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

pub use traffic_jwt::key::SigningKeySource;
pub use traffic_jwt::key::{validate_reference, validate_source};

pub use traffic_engine_policy::signing::ResolvedSigningKey;

pub fn resolve(root: &Path, source: &SigningKeySource) -> Result<ResolvedSigningKey> {
    ResolvedSigningKey::resolve(root, source, load)
}

pub fn load(
    root: &Path,
    source: &SigningKeySource,
) -> Result<traffic_engine_policy::signing::SigningKeyMaterial> {
    Ok((
        resolve_source(root, source)?,
        source_witnesses(root, source)?,
    ))
}

pub fn resolve_source(root: &Path, source: &SigningKeySource) -> Result<Vec<u8>> {
    validate_source(source)?;
    let value = match source {
        SigningKeySource::TargetEnv { name } => {
            crate::startup::startup_environment_value(root, name).map_err(|_| anyhow::anyhow!("cannot resolve JWT signing key from target startup environment"))?.context("JWT signing key is absent from the effective target environment; explicitly select a mounted file if the application loads dotenv itself")?
        }
        SigningKeySource::TargetFile { path, field } => {
            let startup = crate::config::project::config::load_target_startup(root)?;
            let snapshot = crate::startup::load_startup_snapshot(root, &startup)?;
            ensure!(
                snapshot
                    .mounts()
                    .iter()
                    .any(|m| !m.writable && path.starts_with(&m.path)),
                "JWT key file must be within a declared read-only startup mount"
            );
            let host = crate::startup::startup_mount_source(root, path)?;
            let entries = dotenvy::from_path_iter(&host)
                .map_err(|_| anyhow::anyhow!("cannot parse JWT startup key file"))?;
            let mut found = None;
            for entry in entries {
                let (name, value) =
                    entry.map_err(|_| anyhow::anyhow!("invalid JWT startup key file entry"))?;
                if name == *field {
                    ensure!(found.is_none(), "duplicate JWT key field in startup file");
                    found = Some(value);
                }
            }
            found.context("JWT signing key field is absent from startup file")?
        }
    };
    ensure!(!value.trim().is_empty(), "JWT signing key is empty");
    Ok(value.into_bytes())
}

fn source_witnesses(root: &Path, source: &SigningKeySource) -> Result<Vec<(PathBuf, String)>> {
    let paths = match source {
        SigningKeySource::TargetEnv { .. } => {
            crate::startup::startup_environment_witness_paths(root)?
        }
        SigningKeySource::TargetFile { path, .. } => vec![
            root.join(crate::repository::LOCAL_STARTUP_MANIFEST_PATH),
            crate::startup::startup_mount_source(root, path)?,
        ],
    };
    paths
        .into_iter()
        .map(|path| {
            use sha2::{Digest, Sha256};
            let metadata = std::fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() <= 16 * 1024 * 1024,
                "signing input witness must be a bounded regular file"
            );
            let bytes = std::fs::read(&path)?;
            ensure!(
                bytes.len() <= 16 * 1024 * 1024,
                "signing input witness exceeds bound"
            );
            Ok((path, format!("sha256:{:x}", Sha256::digest(bytes))))
        })
        .collect()
}
