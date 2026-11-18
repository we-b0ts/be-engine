//! Authenticated source traversal and shared transport outcome validation.
use super::*;
use serde::de::DeserializeOwned;

pub fn validate_outcome(value: &Value) -> Result<()> {
    if value["event_type"] == "dependency_connect_failure" {
        let failure: connect_failure::RecordedFailure = serde_json::from_value(value.clone())?;
        failure.validate()?;
    }
    if let Some(outcome) = value.get("outcome") {
        let outcome = serde_json::from_value::<crate::DependencyExchangeOutcome>(outcome.clone())?;
        outcome.validate()?;
        if outcome.termination().is_some() {
            anyhow::ensure!(
                value
                    .get("duration_ms")
                    .and_then(Value::as_u64)
                    .is_some_and(|duration| duration <= 86_400_000),
                "transport termination requires an explicit bounded request-relative duration_ms"
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub struct RecordedProxyError {
    pub protocol: String,
    pub error: String,
}

pub struct SourceRecords<R> {
    pub records: Vec<(usize, R)>,
    pub scope: execution_plan::SourceScopeIdentity,
    pub facts: Vec<report::unused_source::CaptureFact>,
}

pub async fn read_dependency_file<R: DeserializeOwned + Send + 'static>(
    path: &Path,
) -> Result<SourceRecords<R>> {
    let original = path.to_owned();
    let (records, scope, facts) = tokio::task::spawn_blocking(move || -> Result<_> {
        use sha2::Digest;
        let mut hash = sha2::Sha256::new();
        let mut source_bytes = 0_u64;
        let mut input = crate::dependency_index::RecordStream::open(&original)?;
        let mut records = Vec::new();
        let mut facts = Vec::new();
        while let Some((location, raw)) = input.next()? {
            hash.update(raw);
            source_bytes += raw.len() as u64;
            if raw.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let value: Value = serde_json::from_slice(raw)?;
            validate_outcome(&value)?;
            if let Some(fact) = report::unused_source::CaptureFact::from_record(&value) {
                facts.push(fact);
            }
            records.push((location.line, serde_json::from_value::<R>(value)?));
        }
        Ok((
            records,
            super::execution_plan::SourceScopeIdentity {
                sha256: format!("{:x}", hash.finalize()),
                source_bytes,
            },
            facts,
        ))
    })
    .await
    .context("dependency scope read task failed")??;
    Ok(SourceRecords {
        records,
        scope,
        facts,
    })
}

pub fn parse_dependency_records<R: DeserializeOwned>(
    path: &Path,
    raw: &str,
) -> Result<Vec<(usize, R)>> {
    let mut records = Vec::new();
    for (line_index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)?;
        validate_outcome(&value).with_context(|| {
            format!(
                "invalid dependency termination at line {} in {}",
                line_index + 1,
                path.display()
            )
        })?;
        let record: R = serde_json::from_value(value).with_context(|| {
            format!(
                "failed to parse dependency replay line {} in {}",
                line_index + 1,
                path.display()
            )
        })?;
        records.push((line_index + 1, record));
    }

    Ok(records)
}

pub use traffic_protocol::connection::endpoint_from_addr as target_from_addr;

pub struct SourceBatch<'a, R> {
    pub path: &'a Path,
    pub records: Vec<(usize, R)>,
    pub skip: &'a BTreeSet<usize>,
    pub source: ReplaySource,
    pub case: Option<&'a str>,
    pub process_rules: &'a [crate::BackgroundDependencyRuleConfig],
    pub cleanup: &'a BTreeSet<crate::replay::RecordedReference>,
}
