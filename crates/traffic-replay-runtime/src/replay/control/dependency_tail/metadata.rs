//! Read bounded immutable tail inventories before Target admission.
use super::{MAX_SELECTED_REFS, RecordedReference};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;
use traffic_protocol::evidence::EvidenceRegistry;

mod async_inventory;
mod interaction_inventory;
mod references;
#[cfg(test)]
mod scope_tests;
pub(super) use references::reference;

const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;

pub(super) struct Metadata {
    recorded_idle_completion: bool,
    pub normal_completion: bool,
    pub request_timeout_ms: u64,
    pub interaction_post_input_ms: Option<u64>,
    pub references: Vec<RecordedReference>,
    pub strict_references: BTreeSet<RecordedReference>,

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
    capture_complete: bool,
    business_complete: bool,
    business_completion: String,
    inventory_complete: bool,
    completed_refs: Vec<RecordedReference>,
    #[serde(default)]
    source_stop_required: Option<bool>,
    #[serde(default)]
    source_stop_after_ms: Option<u64>,
    #[serde(default)]
    cleanup_refs: Vec<RecordedReference>,
    #[serde(default)]
    ending: Option<EndingObservation>,
    #[serde(default)]
    idle_completion: Option<IdleObservation>,
}

#[derive(Deserialize)]
struct IdleObservation {
    quiet_ms: u64,
}

#[derive(Deserialize)]
struct EndingObservation {
    reason: String,
    probe_ms: u64,
    started_after_ms: u64,
    elapsed_ms: u64,
}

pub(super) async fn load(
    case_dir: &Path,
    async_rules: &crate::recorder::async_api::CompletionPolicy,
    request_timeout: Duration,
    evidence: &EvidenceRegistry,
) -> Result<Option<Metadata>> {
    let mut metadata = if let Some(raw) = read(&case_dir.join("async-api-observation.json")).await?
    {
        Some(async_metadata(&raw)?)
    } else {
        async_inventory::from_complete_source(case_dir, async_rules, request_timeout, evidence)
            .await?
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
                recorded_idle_completion: false,
                normal_completion: true,
                request_timeout_ms: observation.request_timeout_ms,
                interaction_post_input_ms: None,
                references: observation.completed_refs,
                strict_references: BTreeSet::new(),

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
                .cloned()
                .chain(general.references)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            // An async inventory contains all case-owned work and cannot be
            // downgraded by older process-owned/quiet-window exemptions.
            metadata
                .strict_references
                .extend(metadata.references.iter().cloned());
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
                .cloned()
                .chain(legacy.references)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
        } else {
            metadata = Some(legacy);
        }
    }
    if metadata.is_none() {
        metadata = interaction_inventory::from_complete_source(case_dir, request_timeout, evidence)
            .await?;
    }
    if let Some(metadata) = &metadata {
        validate(metadata)?;
    }
    Ok(metadata)
}

pub(super) async fn load_effective(
    case_dir: &Path,
    dependencies: &Path,
    async_rules: &crate::recorder::async_api::CompletionPolicy,
    request_timeout: Duration,
    evidence: &EvidenceRegistry,
) -> Result<Option<Metadata>> {
    let original = crate::dependency_index::scoped::case_path(case_dir);
    let derived = crate::dependency_index::scoped::view_path(dependencies).is_some()
        && dependencies != original
        && dependencies != case_dir.join("dependencies.jsonl");
    let empty = crate::recorder::async_api::CompletionPolicy::default();
    let mut metadata = load(
        case_dir,
        if derived { &empty } else { async_rules },
        request_timeout,
        evidence,
    )
    .await?;
    if !derived {
        return Ok(metadata);
    }
    let recorded_idle = metadata
        .as_ref()
        .is_some_and(|tail| tail.recorded_idle_completion);
    if !recorded_idle
        && let Some(mut effective) = async_inventory::from_scope(
            case_dir,
            dependencies,
            async_rules,
            request_timeout,
            evidence,
        )
        .await?
    {
        if let Some(captured) = metadata {
            effective.source_stop_required |= captured.source_stop_required;
            effective.source_stop_after_ms = captured.source_stop_after_ms;
            effective.cleanup_refs = captured.cleanup_refs;
        }
        validate(&effective)?;
        return Ok(Some(effective));
    }
    if let Some(tail) = &mut metadata {
        let path = dependencies.to_owned();
        let evidence = evidence.clone();
        let references =
            tokio::task::spawn_blocking(move || -> Result<BTreeSet<RecordedReference>> {
                let mut input = crate::dependency_index::RecordStream::open(&path)?;
                let mut references = BTreeSet::new();
                while let Some((_, raw)) = input.next()? {
                    if raw.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    if let Some(item) = reference(&serde_json::from_slice(raw)?, &evidence)? {
                        let inserted = references.insert(item);
                        ensure!(
                            !recorded_idle || inserted,
                            "async Source inventory repeats an exchange"
                        );
                        ensure!(
                            references.len() <= MAX_SELECTED_REFS,
                            "effective tail inventory exceeds its bound"
                        );
                    }
                }
                Ok(references)
            })
            .await
            .context("effective tail inventory task failed")??;
        if recorded_idle {
            // An observed idle fallback permits normal finite replay without
            // a matched end. The derived scope still requires every newly
            // assigned semantic exchange to be consumed.
            tail.strict_references = references.clone();
        } else {
            tail.strict_references
                .retain(|item| references.contains(item));
        }
        tail.cleanup_refs.retain(|item| references.contains(item));
        tail.references = references.into_iter().collect();
        validate(tail)?;
    }
    Ok(metadata)
}

fn async_metadata(raw: &[u8]) -> Result<Metadata> {
    let observation: AsyncObservation =
        serde_json::from_slice(raw).context("invalid async API observation metadata")?;
    ensure!(
        observation.version == 2,
        "unsupported async API observation version"
    );
    ensure!(
        observation.capture_complete && observation.inventory_complete,
        "async API exchange inventory is incomplete"
    );
    ensure!(
        matches!(
            observation.end_reason.as_str(),
            "resource" | "idle" | "dependency_failure" | "timeout" | "stopped"
        ),
        "async API observation has an unknown completion reason"
    );
    if let Some(ending) = &observation.ending {
        ensure!(
            observation.end_reason == "resource"
                && ending.probe_ms == 1_000
                && ending
                    .started_after_ms
                    .checked_add(ending.elapsed_ms)
                    .is_some()
                && ending.reason == "probe_completed"
                && ending.elapsed_ms >= ending.probe_ms,
            "async ending requires a candidate and a completed request-start probe"
        );
    }
    ensure!(
        match (
            &observation.idle_completion,
            observation.end_reason.as_str()
        ) {
            (Some(idle), "idle") => idle.quiet_ms == 300_000 && observation.ending.is_none(),
            (None, reason) => reason != "idle",
            _ => false,
        },
        "async idle completion requires the five-minute business inactivity observation"
    );
    ensure!(
        observation.business_complete
            == (observation.end_reason == "resource" && observation.ending.is_none())
            && observation.business_completion
                == if observation.business_complete {
                    "observed"
                } else {
                    "unobserved"
                },
        "async API business completion facts are inconsistent"
    );
    let failure_end = !matches!(observation.end_reason.as_str(), "resource" | "idle");
    let source_stop_required = observation.source_stop_required.unwrap_or(failure_end);
    ensure!(
        observation.completed_refs.len() <= MAX_SELECTED_REFS,
        "async API dependency inventory exceeds its bound"
    );
    let references = observation
        .completed_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let cleanup = observation
        .cleanup_refs
        .iter()
        .cloned()
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
            .is_none_or(|_| source_stop_required),
        "async Source-stop clock has no lifecycle owner"
    );
    ensure!(
        !failure_end || source_stop_required,
        "async failure/deadline completion cannot reuse the stopped Source process"
    );
    let metadata = Metadata {
        recorded_idle_completion: observation.end_reason == "idle",
        normal_completion: matches!(observation.end_reason.as_str(), "resource" | "idle"),
        request_timeout_ms: observation.request_timeout_ms,
        interaction_post_input_ms: None,
        strict_references: references,
        references: observation.completed_refs,

        source_stop_required,
        source_stop_after_ms: observation.source_stop_after_ms,
        cleanup_refs: cleanup,
        failure_completion: matches!(
            observation.end_reason.as_str(),
            "dependency_failure" | "stopped"
        ),
        timeout_completion: observation.end_reason == "timeout",
    };
    validate(&metadata)?;
    Ok(metadata)
}

pub(crate) fn load_cleanup_refs(case_dir: &Path) -> Result<BTreeSet<RecordedReference>> {
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
        recorded_idle_completion: false,
        normal_completion: true,
        request_timeout_ms: observation.request_timeout_ms,
        interaction_post_input_ms: None,
        strict_references: observation
            .selected_completed_refs
            .iter()
            .cloned()
            .collect(),
        references: observation.selected_completed_refs,

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

/// Native requirements are selected from the captured Source scenario.
pub(super) async fn completion_requirements(
    case_dir: &Path,
    rules: &crate::recorder::async_api::CompletionPolicy,
) -> Result<crate::recorder::async_api::CompletionRequirements> {
    let captured = read(&case_dir.join("async-api-observation.json"))
        .await?
        .map(|raw| serde_json::from_slice::<serde_json::Value>(&raw))
        .transpose()?;
    Ok(rules.requirements(captured.as_ref()))
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
        json!({"version":2,"request_timeout_ms":100,"end_reason":"timeout",
            "capture_complete":true,"business_complete":false,"business_completion":"unobserved","inventory_complete":true,"source_stop_required":true,
            "source_stop_after_ms":100,"completed_refs":[reference],"cleanup_refs":[reference]})
    }

    #[test]
    fn completed_candidate_probe_is_normal_capture_without_claiming_business_completion() {
        let mut value = observation();
        value["end_reason"] = json!("resource");
        value["request_timeout_ms"] = json!(5000);
        value["source_stop_required"] = json!(false);
        value["source_stop_after_ms"] = Value::Null;
        value["cleanup_refs"] = json!([]);
        value["ending"] = json!({"reason":"probe_completed","probe_ms":1000,
            "started_after_ms":10,"elapsed_ms":1001});
        let metadata = async_metadata(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(metadata.normal_completion);
        assert!(!metadata.failure_completion);
        assert!(!metadata.timeout_completion);
        assert!(!metadata.source_stop_required);
        for field in ["reason", "probe_ms", "elapsed_ms"] {
            let mut invalid = value.clone();
            invalid["ending"][field] = match field {
                "reason" => json!("limit"),
                _ => json!(0),
            };
            assert!(async_metadata(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        value["ending"]["started_after_ms"] = json!(172_800_000_u64);
        value["ending"]["elapsed_ms"] = json!(172_800_001_u64);
        assert!(async_metadata(&serde_json::to_vec(&value).unwrap()).is_ok());
        let mut overflow = value.clone();
        overflow["ending"]["started_after_ms"] = json!(u64::MAX);
        assert!(async_metadata(&serde_json::to_vec(&overflow).unwrap()).is_err());
        value["business_complete"] = json!(true);
        value["business_completion"] = json!("observed");
        assert!(async_metadata(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn explicit_stop_has_a_distinct_unfinished_capture_reason_without_a_day_limit() {
        let mut value = observation();
        value["end_reason"] = json!("stopped");
        value["source_stop_after_ms"] = json!(172_800_000_u64);
        let metadata = async_metadata(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!metadata.normal_completion);
        assert!(metadata.failure_completion);
        assert!(!metadata.timeout_completion);
        assert!(metadata.source_stop_required);
    }

    #[test]
    fn business_idle_capture_replays_normally_without_a_fabricated_terminal() {
        let mut value = observation();
        value["end_reason"] = json!("idle");
        value["source_stop_required"] = json!(false);
        value["source_stop_after_ms"] = Value::Null;
        value["cleanup_refs"] = json!([]);
        value["idle_completion"] = json!({"quiet_ms":300_000});
        let metadata = async_metadata(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(metadata.normal_completion);
        assert!(!metadata.failure_completion);
        assert!(!metadata.timeout_completion);
        assert!(!metadata.source_stop_required);
        for marker in [Value::Null, json!({"quiet_ms":1000})] {
            value["idle_completion"] = marker;
            assert!(async_metadata(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
    #[test]
    fn only_complete_owned_resources_can_be_classified_as_lifecycle_cleanup() {
        let valid = observation();
        let metadata = async_metadata(&serde_json::to_vec(&valid).unwrap()).unwrap();
        assert!(metadata.source_stop_required);
        assert_eq!(metadata.source_stop_after_ms, Some(100));
        assert_eq!(metadata.cleanup_refs, metadata.strict_references);
        for change in 0..10 {
            let mut invalid = valid.clone();
            match change {
                0 => invalid["source_stop_required"] = json!(false),
                1 => invalid["cleanup_refs"][0]["exchange_id"] = json!(uuid::Uuid::new_v4()),
                2 => invalid["cleanup_refs"]
                    .as_array_mut()
                    .unwrap()
                    .push(valid["cleanup_refs"][0].clone()),
                3 => invalid["inventory_complete"] = json!(false),
                4 => invalid["capture_complete"] = json!(false),
                5 => invalid["source_stop_after_ms"] = Value::Null,
                6 => invalid["source_stop_after_ms"] = json!(-1),
                7 => invalid["business_complete"] = json!(true),
                8 => invalid["business_completion"] = json!("observed"),
                _ => invalid["version"] = json!(1),
            }
            assert!(
                async_metadata(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                "change {change}"
            );
        }
        let mut resource = valid;
        resource["end_reason"] = json!("resource");
        resource["business_complete"] = json!(true);
        resource["business_completion"] = json!("observed");
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
