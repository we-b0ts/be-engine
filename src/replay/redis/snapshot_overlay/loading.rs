//! Bound selected snapshot proof before reading additional response payloads.
use super::*;
use crate::dependency_index::{RecordReader, RecordSource, RecordStream};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(super) struct EvidenceCollector {
    pub(super) entries: Vec<SnapshotEvidence>,
    bytes: usize,
}

impl EvidenceCollector {
    fn push(&mut self, entry: SnapshotEvidence) -> Result<()> {
        ensure!(
            self.entries.len() < MAX_MATCHING_EXCHANGES,
            "Redis snapshot evidence exceeds the {MAX_MATCHING_EXCHANGES} exchange evidence limit"
        );
        self.bytes = entry
            .args
            .iter()
            .try_fold(self.bytes, |total, arg| total.checked_add(arg.len()))
            .and_then(|total| total.checked_add(entry.response.len()))
            .context("Redis snapshot evidence byte count overflowed")?;
        ensure!(
            self.bytes <= MAX_MATCHING_BYTES,
            "Redis snapshot evidence exceeds the {MAX_MATCHING_BYTES} byte evidence limit"
        );
        self.entries.push(entry);
        Ok(())
    }
}

pub(super) fn replay_evidence(
    exchanges: &[ReplayExchange],
    rule: &BackgroundDependencyRuleConfig,
) -> Result<Vec<SnapshotEvidence>> {
    let mut evidence = EvidenceCollector::default();
    for (index, exchange) in exchanges.iter().enumerate().filter(|(_, exchange)| {
        redis_rule_matches(
            rule,
            exchange.record.target_port,
            &exchange.record.command,
            &exchange.args,
        )
    }) {
        evidence.push(evidence_from_replay(index, exchange)?)?;
    }
    Ok(evidence.entries)
}

pub(super) fn read_snapshot_evidence(
    path: &Path,
    source: ReplaySource,
    rule: &BackgroundDependencyRuleConfig,
    evidence: &mut EvidenceCollector,
) -> Result<()> {
    if source == ReplaySource::Global {
        return read_global(path, rule, evidence);
    }
    let mut input = RecordStream::open(path)?;
    while let Some((location, raw)) = input.next()? {
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let record = serde_json::from_slice(raw).with_context(|| {
            format!(
                "invalid dependency JSON at {} line {}",
                path.display(),
                location.line
            )
        })?;
        observe(record, source, rule, evidence)?;
    }
    Ok(())
}

fn read_global(
    path: &Path,
    rule: &BackgroundDependencyRuleConfig,
    evidence: &mut EvidenceCollector,
) -> Result<()> {
    let (index, root) = crate::dependency_index::global::load_global_index(
        path,
        crate::replay::validate_index_record,
    )?;
    let pages = crate::dependency_index::global::global_records(&index, &root)?;
    let source = RecordSource::new(
        path,
        index.stamp,
        Arc::new(Mutex::new(RecordReader::new(MAX_MATCHING_BYTES))),
    );
    for page in 0..pages.pages() {
        for entry in pages.read_page(page)? {
            let record = serde_json::from_value::<DependencyRecord>(entry.record)?;
            if let DependencyRecord::RedisExchange(exchange) = &record {
                if !matches_rule(exchange, rule)? {
                    continue;
                }
                let original = source
                    .reference(entry.location)
                    .load::<RecordedExchange>()?;
                evidence.push(evidence_from_record(None, ReplaySource::Global, original)?)?;
            } else {
                observe(record, ReplaySource::Global, rule, evidence)?;
            }
        }
    }
    source.validate()
}

fn matches_rule(
    exchange: &RecordedExchange,
    rule: &BackgroundDependencyRuleConfig,
) -> Result<bool> {
    let args = exchange
        .args
        .iter()
        .map(|capture| capture.decode())
        .collect::<Result<Vec<_>>>()?;
    Ok(redis_rule_matches(
        rule,
        exchange.target_port,
        &exchange.command,
        &args,
    ))
}

fn observe(
    record: DependencyRecord,
    source: ReplaySource,
    rule: &BackgroundDependencyRuleConfig,
    evidence: &mut EvidenceCollector,
) -> Result<()> {
    match record {
        DependencyRecord::RedisExchange(exchange) if matches_rule(&exchange, rule)? => {
            evidence.push(evidence_from_record(None, source, *exchange)?)?;
        }
        DependencyRecord::ProxyError(error) if error.protocol == "redis" => {
            return Err(anyhow!(
                "Redis snapshot evidence contains a proxy error: {}",
                error.error
            ));
        }
        _ => {}
    }
    Ok(())
}
