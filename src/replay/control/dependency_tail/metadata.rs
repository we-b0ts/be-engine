//! Read bounded immutable tail inventories before Target admission.
use super::{MAX_SELECTED_REFS, RecordedReference};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;

pub(super) struct Metadata {
    pub request_timeout_ms: u64,
    pub references: Vec<RecordedReference>,
    pub strict_references: BTreeSet<RecordedReference>,
    pub process_owned_exemptions: bool,
}

#[derive(Deserialize)]
struct LegacyObservation {
    version: u32,
    request_timeout_ms: u64,
    selected_completed_refs: Vec<RecordedReference>,
    #[serde(default)]
    inventory_complete: Option<bool>,
}

#[derive(Deserialize)]
struct DependencyTailObservation {
    version: u32,
    request_timeout_ms: u64,
    outcome: String,
    inventory_complete: bool,
    completed_refs: Vec<RecordedReference>,
}

pub(super) async fn load(case_dir: &Path) -> Result<Option<Metadata>> {
    let mut metadata =
        if let Some(raw) = read(&case_dir.join("dependency-tail-observation.json")).await? {
            let observation: DependencyTailObservation = serde_json::from_slice(&raw)
                .context("invalid dependency-tail observation metadata")?;
            ensure!(
                observation.version == 1,
                "unsupported dependency-tail observation version"
            );
            ensure!(
                observation.outcome == "quiet",
                "dependency-tail observation did not complete normally"
            );
            ensure!(
                observation.inventory_complete,
                "dependency-tail exchange inventory is incomplete"
            );
            Some(Metadata {
                request_timeout_ms: observation.request_timeout_ms,
                references: observation.completed_refs,
                strict_references: BTreeSet::new(),
                process_owned_exemptions: true,
            })
        } else {
            None
        };
    if let Some(metadata) = &metadata {
        validate(metadata)?;
    }
    if let Some(raw) = read(&case_dir.join("api-origin-observation.json")).await? {
        let legacy = legacy(&raw)?;
        if let Some(metadata) = &mut metadata {
            // A general stream inventory cannot revoke previously declared
            // API-origin business obligations. Preserve their exact identity
            // and strictness, including references absent from the new file.
            metadata.strict_references = legacy.strict_references;
            metadata.references = metadata
                .references
                .iter()
                .copied()
                .chain(legacy.references)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
        } else {
            metadata = Some(legacy);
        }
    }
    if let Some(metadata) = &metadata {
        validate(metadata)?;
    }
    Ok(metadata)
}

fn legacy(raw: &[u8]) -> Result<Metadata> {
    let observation: LegacyObservation =
        serde_json::from_slice(raw).context("invalid legacy dependency observation metadata")?;
    ensure!(
        observation.version == 1,
        "unsupported legacy dependency observation version"
    );
    ensure!(
        observation.inventory_complete != Some(false),
        "legacy dependency observation exchange inventory is incomplete"
    );
    let metadata = Metadata {
        request_timeout_ms: observation.request_timeout_ms,
        strict_references: observation
            .selected_completed_refs
            .iter()
            .copied()
            .collect(),
        references: observation.selected_completed_refs,
        process_owned_exemptions: false,
    };
    validate(&metadata)?;
    Ok(metadata)
}

fn validate(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.request_timeout_ms > 0,
        "dependency observation requires a nonzero absolute request budget"
    );
    ensure!(
        metadata.references.len() <= MAX_SELECTED_REFS,
        "dependency observation exchange inventory exceeds its bound"
    );
    ensure!(
        metadata.references.iter().collect::<BTreeSet<_>>().len() == metadata.references.len(),
        "dependency observation repeats an exchange reference"
    );
    Ok(())
}

async fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    let metadata = match tokio::fs::metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed to inspect dependency observation"),
    };
    ensure!(
        metadata.is_file(),
        "dependency observation is not a regular file"
    );
    ensure!(
        metadata.len() <= MAX_METADATA_BYTES,
        "dependency observation exceeds its metadata bound"
    );
    let raw = tokio::fs::read(path)
        .await
        .context("failed to read dependency observation")?;
    ensure!(
        raw.len() as u64 <= MAX_METADATA_BYTES,
        "dependency observation exceeds its metadata bound"
    );
    Ok(Some(raw))
}
