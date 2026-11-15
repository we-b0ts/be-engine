//! Named signing-key sources and their pure configuration validation.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SigningKeySource {
    TargetEnv { name: String },
    TargetFile { path: PathBuf, field: String },
}

pub fn validate_reference(reference: &str) -> Result<()> {
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

pub fn validate_source(source: &SigningKeySource) -> Result<()> {
    match source {
        SigningKeySource::TargetEnv { name } => validate_reference(name),
        SigningKeySource::TargetFile { path, field } => {
            ensure!(path.is_absolute(), "JWT key file path must be absolute");
            validate_reference(field)
        }
    }
}
