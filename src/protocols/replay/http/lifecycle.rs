//! Exact async Source-stop context for immutable, incomplete HTTP evidence.
use super::*;

#[cfg(test)]
const ENGINE_CLEANUP: &str =
    "HTTP dependency response ended during engine cleanup before capture completed";

impl RecordedHttpExchange {
    pub(crate) fn exchange_id(&self) -> Option<uuid::Uuid> {
        self.native.id.as_deref()?.parse().ok()
    }

    /// Called only for a case's exact, validated async cleanup reference.
    pub(crate) fn authorize_lifecycle_cleanup(&mut self) -> Result<()> {
        validate_record(self)?;
        self.cleanup_authorized = true;
        Ok(())
    }
}

pub(super) fn validate_record(record: &RecordedHttpExchange) -> Result<()> {
    record
        .native
        .validate_cleanup(record.response_evidence.is_some())
}

#[cfg(test)]
mod tests;
