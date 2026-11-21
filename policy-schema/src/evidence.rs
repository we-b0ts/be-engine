//! Bounded persisted Source-evidence descriptions.
use anyhow::{Result, bail};

pub fn validate_optional_source_evidence(source_evidence: &str) -> Result<()> {
    if source_evidence.is_empty() {
        Ok(())
    } else {
        validate_source_evidence(source_evidence)
    }
}

pub fn validate_source_evidence(source_evidence: &str) -> Result<()> {
    validate_single_line("dependency source evidence", source_evidence, 1_024)
}

pub fn validate_single_line(label: &str, value: &str, max_len: usize) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} must not be empty");
    }
    if value != value.trim() || value.contains(['\r', '\n']) {
        bail!("{label} must be a single line without surrounding whitespace");
    }
    if value.len() > max_len {
        bail!("{label} must not exceed {max_len} bytes");
    }
    Ok(())
}
