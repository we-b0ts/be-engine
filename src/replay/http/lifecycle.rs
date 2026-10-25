//! Exact async Source-stop context for immutable, incomplete HTTP evidence.
use super::*;

const ENGINE_CLEANUP: &str =
    "HTTP dependency response ended during engine cleanup before capture completed";

impl RecordedHttpExchange {
    pub(in crate::replay) fn exchange_id(&self) -> Option<uuid::Uuid> {
        self.id.as_deref()?.parse().ok()
    }

    /// Called only for a case's exact, validated async cleanup reference.
    pub(in crate::replay) fn authorize_lifecycle_cleanup(&mut self) -> Result<()> {
        validate_record(self)?;
        self.cleanup_authorized = true;
        Ok(())
    }
}

pub(super) fn validate_record(record: &RecordedHttpExchange) -> Result<()> {
    anyhow::ensure!(
        !record.request_body.truncated,
        "async HTTP cleanup request was truncated"
    );
    anyhow::ensure!(
        record
            .duration_ms
            .as_ref()
            .and_then(Value::as_u64)
            .is_some_and(|value| value <= 86_400_000),
        "async HTTP cleanup needs bounded request timing"
    );
    anyhow::ensure!(
        record.outcome != crate::DependencyExchangeOutcome::NoResponse,
        "HTTP cleanup cannot claim a protocol no-response command"
    );
    anyhow::ensure!(
        record
            .outcome
            .termination()
            .is_none_or(|end| end.side != crate::dependency::TerminationSide::Engine),
        "async cleanup preserves Source evidence instead of inventing engine peer outcomes"
    );
    if let Some(stream) = &record.response_stream {
        anyhow::ensure!(
            stream.version == 2,
            "async HTTP cleanup prefix requires flushed-prefix evidence version 2"
        );
        anyhow::ensure!(
            record.response_status.is_some() && record.response_headers.is_some(),
            "async HTTP cleanup prefix has no headers"
        );
        anyhow::ensure!(
            stream.trailers.is_none(),
            "async HTTP cleanup cannot contain response EOF trailers"
        );
        anyhow::ensure!(
            record
                .error
                .as_deref()
                .is_none_or(|error| error == ENGINE_CLEANUP),
            "async HTTP cleanup prefix contains an independent capture error"
        );
        let body = record
            .response_body
            .as_ref()
            .context("async HTTP cleanup prefix has no payload")?;
        anyhow::ensure!(!body.truncated, "async HTTP cleanup prefix was truncated");
        let payload_len = if record.response_evidence.is_some() {
            body.stored_len
                .context("deferred HTTP cleanup prefix has no length")?
        } else {
            decode_body(body)?.len()
        };
        stream.validate_prefix(payload_len)?;
        anyhow::ensure!(
            record.duration_ms.as_ref().and_then(Value::as_u64) == Some(stream.end_ms),
            "async HTTP cleanup duration disagrees with its captured prefix"
        );
    } else {
        anyhow::ensure!(
            record.response_status.is_none() && record.response_headers.is_none(),
            "async HTTP cleanup without stream evidence cannot claim response headers"
        );
        anyhow::ensure!(
            record
                .response_body
                .as_ref()
                .map(decode_body)
                .transpose()?
                .is_none_or(|bytes| bytes.is_empty()),
            "async HTTP cleanup has untracked response bytes"
        );
        anyhow::ensure!(
            record.outcome.termination().is_some() || upstream_failure::is_recorded(record),
            "async HTTP cleanup has no incomplete transport evidence"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
