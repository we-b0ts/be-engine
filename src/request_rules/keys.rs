//! Signing-key sources. Values are resolved from target startup inputs, never
//! serialized into plans, policy, command arguments, or diagnostics.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SigningKeySource {
    TargetEnv { name: String },
    TargetFile { path: PathBuf, field: String },
}

pub(crate) fn validate_reference(reference: &str) -> Result<()> {
    ensure!(
        !reference.is_empty()
            && reference.len() <= 128
            && reference
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
        "invalid JWT rule id or signing key reference"
    );
    Ok(())
}

pub(crate) fn validate_source(source: &SigningKeySource) -> Result<()> {
    match source {
        SigningKeySource::TargetEnv { name } => validate_reference(name),
        SigningKeySource::TargetFile { path, field } => {
            ensure!(path.is_absolute(), "JWT key file path must be absolute");
            validate_reference(field)
        }
    }
}

pub(crate) fn resolve_source(root: &Path, source: &SigningKeySource) -> Result<Vec<u8>> {
    validate_source(source)?;
    let value = match source {
        SigningKeySource::TargetEnv { name } => {
            crate::startup::startup_environment_value(root, name).map_err(|_| anyhow::anyhow!("cannot resolve JWT signing key from target startup environment"))?.context("JWT signing key is absent from the effective target environment; explicitly select a mounted file if the application loads dotenv itself")?
        }
        SigningKeySource::TargetFile { path, field } => {
            let (_, config) = crate::e2e_run::resolve_project(root)?;
            let snapshot = crate::startup::load_startup_snapshot(root, &config.target_startup)?;
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
