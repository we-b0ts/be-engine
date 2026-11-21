//! Validation of external runtime identities and reconciliation observations.
use crate::RewriteWorkerMissingQuery;
use anyhow::{Context, Result, ensure};

pub fn validate_runtime_query(query: &RewriteWorkerMissingQuery) -> Result<()> {
    validate_identity("runtime query API or command", &query.api_or_command, 4_096)?;
    validate_identity("runtime query time", &query.queried_at, 128)?;
    chrono::DateTime::parse_from_rfc3339(&query.queried_at)
        .context("runtime query time must be RFC 3339 with a timezone")?;
    Ok(())
}

pub fn validate_identity(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    ensure!(
        value == value.trim() && !value.is_empty() && !value.contains(['\r', '\n']),
        "{label} must be a non-empty single line"
    );
    ensure!(value.len() <= max_bytes, "{label} is too long");
    Ok(())
}
