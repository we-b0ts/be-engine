//! Local signing-key references. Values are resolved from target startup inputs,
//! never serialized into plans, policy, command arguments, or diagnostics.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SigningKeySource {
    TargetEnv { name: String },
    TargetFile { path: PathBuf, field: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyBinding {
    pub(crate) source: SigningKeySource,
    pub(crate) challenge: String,
    pub(crate) revision: String,
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

pub(crate) fn binding_path(root: &Path) -> PathBuf {
    root.join(".traffic-e2e/local/secrets/jwt-signing-keys.json")
}

pub(crate) fn bindings(root: &Path) -> Result<BTreeMap<String, KeyBinding>> {
    let path = binding_path(root);
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("invalid local JWT key bindings"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(_) => anyhow::bail!("cannot read local JWT key bindings"),
    }
}

pub(crate) fn revision(key: &[u8], challenge: &str) -> String {
    STANDARD.encode(super::jwt::sign(
        super::jwt::Algorithm::HS256,
        key,
        challenge.as_bytes(),
    ))
}

pub(crate) fn prepare_binding(
    root: &Path,
    reference: &str,
    source: Option<SigningKeySource>,
) -> Result<(KeyBinding, Vec<u8>)> {
    validate_reference(reference)?;
    let existing = bindings(root)?.remove(reference);
    let source = source.or_else(|| existing.as_ref().map(|b| b.source.clone())).context("JWT signing key reference is not bound; supply --target-env or --target-key-file with --target-key-field")?;
    let key = resolve_source(root, &source)?;
    let challenge = existing
        .as_ref()
        .map(|b| b.challenge.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let revision = revision(&key, &challenge);
    Ok((
        KeyBinding {
            source,
            challenge,
            revision,
        },
        key,
    ))
}

pub(crate) fn resolve_profile_binding(
    root: &Path,
    reference: &str,
    configured_source: Option<&SigningKeySource>,
) -> Result<Vec<u8>> {
    validate_reference(reference)?;
    let binding = bindings(root)?
        .remove(reference)
        .context("JWT signing key reference is not bound; run rule plan/apply")?;
    if let Some(configured_source) = configured_source {
        ensure!(
            &binding.source == configured_source,
            "JWT signing key source changed since rule apply; rerun plan/apply"
        );
    }
    let key = resolve_source(root, &binding.source)?;
    ensure!(
        revision(&key, &binding.challenge) == binding.revision,
        "JWT signing key changed since rule apply; rerun plan/apply"
    );
    Ok(key)
}

pub(crate) fn write_bindings(root: &Path, values: &BTreeMap<String, KeyBinding>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = binding_path(root);
    let parent = path.parent().expect("key binding parent");
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let bytes = serde_json::to_vec_pretty(values)?;
    if path.exists() {
        crate::config::edit::write_atomic(&path, &bytes)?;
    } else {
        crate::config::edit::create_atomic(&path, &bytes)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
