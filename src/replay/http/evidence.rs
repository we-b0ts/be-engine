//! Retain HTTP request identity and defer only the Global response body.
use super::*;
use crate::dependency_index::RecordRef;
use anyhow::ensure;

pub(in crate::replay) fn register_global_exchange(
    mut record: RecordedHttpExchange,
    reference: RecordRef,
    exchanges: &mut Vec<ReplayHttpExchange>,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    process_rules: &[crate::BackgroundDependencyRuleConfig],
) -> Result<()> {
    if record.global_dependency_reason.as_deref() == Some("background_rule") {
        ensure!(
            record
                .global_dependency_matched_by
                .as_deref()
                .is_some_and(|name| !name.trim().is_empty()),
            "Global HTTP background dependency has no recorded ownership marker; fresh capture is required"
        );
        let uri: Uri = record
            .uri
            .parse()
            .context("Global HTTP background URI is invalid")?;
        // The recorded authority is the physical target. An absolute URI must
        // not let a different host borrow the current ownership selector.
        let path: Uri = uri
            .path_and_query()
            .context("Global HTTP background path is missing")?
            .as_str()
            .parse()?;
        ensure!(
            process_rules.iter().any(|rule| rule.matches_http_request(
                &record.method,
                &path,
                record.authority.as_deref()
            )),
            "Global HTTP background dependency {} {} is not covered by the current process-owned policy; fresh capture is required",
            record.method,
            uri.path()
        );
    }
    record.response_evidence = Some(reference);
    register_http_exchange(record, ReplaySource::Global, None, exchanges, targets)?;
    let record = &mut exchanges
        .last_mut()
        .expect("registered HTTP exchange")
        .record;
    if let Some(body) = &mut record.response_body {
        body.data = String::new();
    }
    Ok(())
}

impl RecordedHttpExchange {
    pub(super) fn materialize_response(&mut self) -> Result<()> {
        if let Some(reference) = self.response_evidence.take() {
            self.response_body = reference.load::<RecordedHttpExchange>()?.response_body;
        }
        if let Some(stream) = &self.response_stream {
            let body = self
                .response_body
                .as_ref()
                .context("HTTP stream has no materialized payload")?;
            let payload_len = decode_body(body)?.len();
            anyhow::ensure!(
                body.stored_len.is_none_or(|stored| stored == payload_len),
                "materialized HTTP stream payload does not match its stored length"
            );
            if self.cleanup_authorized {
                stream.validate_prefix(payload_len)?;
            } else {
                stream.validate(payload_len)?;
            }
        }
        Ok(())
    }
}

impl ReplayState {
    pub(in crate::replay) fn visit_global_http_unused(
        &self,
        visitor: &mut dyn FnMut(serde_json::Value) -> Result<()>,
    ) -> Result<()> {
        for item in self.unused_http_iter(ReplaySource::Global, false) {
            visitor(serde_json::to_value(item)?)?;
        }
        Ok(())
    }
    pub(in crate::replay) fn global_http_unused_count(&self) -> usize {
        if let Some(count) = self.http_global_report_usage().count() {
            return count + self.global_http_extra_unused_count();
        }
        self.unused_http_iter(ReplaySource::Global, false).count()
    }
}
