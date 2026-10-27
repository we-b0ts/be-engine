//! Read bounded immutable tail inventories before Target admission.
use super::{MAX_SELECTED_REFS, RecordedReference};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

mod async_inventory;

pub(super) fn reference(event: &serde_json::Value) -> Result<Option<RecordedReference>> {
    async_inventory::reference(event)
}

const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;

pub(super) struct Metadata {
    pub request_timeout_ms: u64,
    pub references: Vec<RecordedReference>,
    pub strict_references: BTreeSet<RecordedReference>,
    pub process_owned_exemptions: bool,
    pub source_stop_required: bool,
    pub source_stop_after_ms: Option<u64>,
    pub cleanup_refs: BTreeSet<RecordedReference>,
    pub failure_completion: bool,
    pub timeout_completion: bool,
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

#[derive(Deserialize)]
struct AsyncObservation {
    version: u32,
    request_timeout_ms: u64,
    end_reason: String,
    complete: bool,
    inventory_complete: bool,
    completed_refs: Vec<RecordedReference>,
    #[serde(default)]
    source_stop_required: Option<bool>,
    #[serde(default)]
    source_stop_after_ms: Option<u64>,
    #[serde(default)]
    cleanup_refs: Vec<RecordedReference>,
}

pub(super) async fn load(
    case_dir: &Path,
    async_rules: &BTreeMap<String, crate::policy::AsyncApiRules>,
    request_timeout: Duration,
) -> Result<Option<Metadata>> {
    let mut metadata = if let Some(raw) = read(&case_dir.join("async-api-observation.json")).await?
    {
        Some(async_metadata(&raw)?)
    } else {
        async_inventory::from_complete_source(case_dir, async_rules, request_timeout).await?
    };
    let general =
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
                source_stop_required: false,
                source_stop_after_ms: None,
                cleanup_refs: BTreeSet::new(),
                failure_completion: false,
                timeout_completion: false,
            })
        } else {
            None
        };
    if let Some(general) = general {
        if let Some(metadata) = &mut metadata {
            metadata.references = metadata
                .references
                .iter()
                .copied()
                .chain(general.references)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            // An async inventory contains all case-owned work and cannot be
            // downgraded by older process-owned/quiet-window exemptions.
            metadata
                .strict_references
                .extend(metadata.references.iter().copied());
        } else {
            metadata = Some(general);
        }
    }
    if let Some(metadata) = &metadata {
        validate(metadata)?;
    }
    if let Some(raw) = read(&case_dir.join("api-origin-observation.json")).await? {
        let legacy = legacy(&raw)?;
        if let Some(metadata) = &mut metadata {
            // A general stream inventory cannot revoke previously declared
            // API-origin business obligations. Preserve their exact identity
            // and strictness, including references absent from the new file.
            metadata.strict_references.extend(legacy.strict_references);
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

fn async_metadata(raw: &[u8]) -> Result<Metadata> {
    let observation: AsyncObservation =
        serde_json::from_slice(raw).context("invalid async API observation metadata")?;
    ensure!(
        observation.version == 1,
        "unsupported async API observation version"
    );
    ensure!(
        observation.complete && observation.inventory_complete,
        "async API exchange inventory is incomplete"
    );
    ensure!(
        matches!(
            observation.end_reason.as_str(),
            "resource" | "dependency_failure" | "timeout"
        ),
        "async API observation has an unknown completion reason"
    );
    let failure_end = observation.end_reason != "resource";
    let source_stop_required = observation.source_stop_required.unwrap_or(failure_end);
    ensure!(
        observation.completed_refs.len() <= MAX_SELECTED_REFS,
        "async API dependency inventory exceeds its bound"
    );
    let references = observation
        .completed_refs
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let cleanup = observation
        .cleanup_refs
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    ensure!(
        observation.cleanup_refs.len() <= MAX_SELECTED_REFS
            && cleanup.len() == observation.cleanup_refs.len()
            && cleanup.is_subset(&references)
            && (observation.cleanup_refs.is_empty()
                || source_stop_required && observation.source_stop_after_ms.is_some()),
        "async lifecycle cleanup references require unique admitted resources and a Source-stop boundary"
    );
    ensure!(
        observation
            .source_stop_after_ms
            .is_none_or(|offset| source_stop_required && offset <= 86_400_000),
        "async Source-stop clock has no bounded lifecycle owner"
    );
    ensure!(
        !failure_end || source_stop_required,
        "async failure/deadline completion cannot reuse the stopped Source process"
    );
    let metadata = Metadata {
        request_timeout_ms: observation.request_timeout_ms,
        strict_references: references,
        references: observation.completed_refs,
        process_owned_exemptions: false,
        source_stop_required,
        source_stop_after_ms: observation.source_stop_after_ms,
        cleanup_refs: cleanup,
        failure_completion: observation.end_reason == "dependency_failure",
        timeout_completion: observation.end_reason == "timeout",
    };
    validate(&metadata)?;
    Ok(metadata)
}

pub(in crate::replay) fn load_cleanup_refs(case_dir: &Path) -> Result<BTreeSet<RecordedReference>> {
    let path = case_dir.join("async-api-observation.json");
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(error).context("failed to inspect async cleanup evidence"),
    };
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_METADATA_BYTES,
        "async cleanup metadata exceeds its immutable evidence bound"
    );
    Ok(async_metadata(&std::fs::read(path)?)?.cleanup_refs)
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
        source_stop_required: false,
        source_stop_after_ms: None,
        cleanup_refs: BTreeSet::new(),
        failure_completion: false,
        timeout_completion: false,
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

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use serde_json::{Value, json};
    fn observation() -> Value {
        let reference = json!({"protocol":"http","exchange_id":uuid::Uuid::nil()});
        json!({"version":1,"request_timeout_ms":100,"end_reason":"timeout",
            "complete":true,"inventory_complete":true,"source_stop_required":true,
            "source_stop_after_ms":100,"completed_refs":[reference],"cleanup_refs":[reference]})
    }
    #[test]
    fn only_complete_owned_resources_can_be_classified_as_lifecycle_cleanup() {
        let valid = observation();
        let metadata = async_metadata(&serde_json::to_vec(&valid).unwrap()).unwrap();
        assert!(metadata.source_stop_required);
        assert_eq!(metadata.source_stop_after_ms, Some(100));
        assert_eq!(metadata.cleanup_refs, metadata.strict_references);
        for change in 0..7 {
            let mut invalid = valid.clone();
            match change {
                0 => invalid["source_stop_required"] = json!(false),
                1 => invalid["cleanup_refs"][0]["exchange_id"] = json!(uuid::Uuid::new_v4()),
                2 => invalid["cleanup_refs"]
                    .as_array_mut()
                    .unwrap()
                    .push(valid["cleanup_refs"][0].clone()),
                3 => invalid["inventory_complete"] = json!(false),
                4 => invalid["complete"] = json!(false),
                5 => invalid["source_stop_after_ms"] = Value::Null,
                _ => invalid["source_stop_after_ms"] = json!(-1),
            }
            assert!(
                async_metadata(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                "change {change}"
            );
        }
        let mut resource = valid;
        resource["end_reason"] = json!("resource");
        assert!(
            async_metadata(&serde_json::to_vec(&resource).unwrap())
                .unwrap()
                .source_stop_required,
            "resource completion may still need Source stop to drain pending I/O"
        );
    }
    #[test]
    fn synchronous_adapter_and_async_case_reader_share_the_same_cleanup_authority() {
        let temp = tempfile::tempdir().unwrap();
        assert!(load_cleanup_refs(temp.path()).unwrap().is_empty());
        let path = temp.path().join("async-api-observation.json");
        let valid = observation();
        std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        assert_eq!(load_cleanup_refs(temp.path()).unwrap().len(), 1);
        let mut invalid = valid;
        invalid["completed_refs"] = json!([]);
        std::fs::write(path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(load_cleanup_refs(temp.path()).is_err());
    }
}
