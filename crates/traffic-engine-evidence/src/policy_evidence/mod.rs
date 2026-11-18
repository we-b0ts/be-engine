//! Protected complete payload witnesses, separate from pure value comparison.
//! Public report projections contain identities, counts and digests, never bodies.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::policy::{Resource, Slot, Surface};

pub mod authentication;
mod catalog;
pub mod hypotheses;
mod limits;
mod payload;
pub use payload::StoredPayload;
mod source;
mod storage;
mod store;
pub use source::SourceRecord;
pub use store::target_key as target_observation_id;
pub use store::{
    AssociationOutcome, ObservationRetention, PreparedRequestSource, RequestAssociation,
    WitnessStore,
};
mod publication;
pub use publication::stage;
mod v2;
pub use v2::read_target;
pub use v2::{ObservationGraph, RunWitnessOwner, TargetMetadata};
mod witnesses;
pub use witnesses::{WitnessEntries, WitnessEntry};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockPair {
    pub source: Option<DateTime<Utc>>,
    pub target: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessClocks {
    pub case: ClockPair,
    pub dependency: ClockPair,
    pub delivery: ClockPair,
}

impl WitnessClocks {
    pub fn comparison(&self) -> traffic_contract::compare::AnchorClocks {
        let pair = |p: &ClockPair| traffic_contract::time::ClockPair {
            source: p.source,
            target: p.target,
        };
        traffic_contract::compare::AnchorClocks::for_request(
            pair(&self.case),
            pair(&self.dependency),
            pair(&self.delivery),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub case_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange_id: Option<String>,
    pub connection_id: Option<String>,
    pub sequence: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessMetadata {
    pub surface: Surface,
    pub source_role: SourceRole,
    pub target_role: TargetRole,
    pub source: SourceIdentity,
    pub resource: Option<Resource>,
    pub operation: String,
    pub slot: Slot,
    pub clocks: WitnessClocks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceRole {
    #[serde(rename = "recorded_dependency_request")]
    DependencyRequest,
    #[serde(rename = "recorded_dependency_response")]
    DependencyResponse,
    #[serde(rename = "recorded_api_response")]
    ApiResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetRole {
    IndependentTargetObservation,
    DerivedDelivery,
    /// Successful wire completion proves an input, never Target generation.
    DeliveredInput,
    Unavailable,
}

impl WitnessMetadata {
    fn validate_roles(&self, has_target: bool) -> Result<()> {
        let source = match self.surface {
            Surface::ApiResponse => SourceRole::ApiResponse,
            Surface::DependencyRequest => SourceRole::DependencyRequest,
            Surface::DependencyResponse => SourceRole::DependencyResponse,
        };
        ensure!(
            self.source_role == source,
            "policy witness Source role disagrees with its surface"
        );
        let valid = if !has_target {
            self.target_role == TargetRole::Unavailable
        } else if self.surface == Surface::DependencyResponse {
            matches!(
                self.target_role,
                TargetRole::DerivedDelivery | TargetRole::DeliveredInput
            )
        } else {
            self.target_role == TargetRole::IndependentTargetObservation
        };
        ensure!(
            valid,
            "derived delivery cannot become independent Target proof"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessRef {
    pub id: String,
    pub metadata: WitnessMetadata,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
    pub source_sha256: String,
    pub target_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_observation_id: Option<String>,
    #[serde(skip)]
    proof: Option<Box<v2::PairProof>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WitnessManifest {
    pub version: u32,
    /// A single filename relative to the published Replay report directory.
    pub artifact: String,
    pub sha256: String,
    pub observed: usize,
    pub recorded: usize,
    pub omitted: usize,
    pub complete: bool,
    pub sealed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witnesses: Vec<WitnessRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observations: Option<ObservationGraph>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_artifact: Option<catalog::GraphArtifact>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authentication: String,
    #[serde(skip)]
    graph_cache: std::sync::OnceLock<(String, std::sync::Arc<ObservationGraph>)>,
}

impl WitnessManifest {
    pub fn source_index(&self) -> Result<witnesses::WitnessIndex<'_>> {
        witnesses::WitnessIndex::new(self)
    }
    pub fn artifact_paths(&self, report: &Path) -> Result<Vec<PathBuf>> {
        self.load_graph(report)?;
        if let Some(graph) = self.graph()
            && !graph.segments.is_empty()
        {
            let mut paths = graph
                .segments
                .iter()
                .map(|segment| storage::named_path(report, &segment.artifact))
                .collect::<Result<Vec<_>>>()?;
            if let Some(reference) = &self.graph_artifact {
                paths.push(storage::named_path(report, &reference.artifact)?);
            }
            return Ok(paths);
        }
        Ok(vec![artifact_path(report, self)?])
    }
    /// Borrow inventory entries before expanding only the selected candidate.
    pub fn witness_entries(&self) -> Result<WitnessEntries<'_>> {
        WitnessEntries::new(self)
    }

    #[cfg(test)]
    pub fn witnesses(&self) -> Result<Vec<WitnessRef>> {
        self.witness_entries()?
            .map(|entry| Ok(entry?.expand()?.into_owned()))
            .collect()
    }
}

pub fn verify_case_clock(witness: &WitnessRef, report: &serde_json::Value) -> Result<()> {
    if witness.target_sha256.is_none() {
        return Ok(());
    }
    let case = report["cases"]
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["case_id"] == witness.metadata.source.case_id)
        })
        .context("Target witness Case is absent from the Replay report")?;
    let clock = case["target_request_started_at"]
        .as_str()
        .map(str::parse::<DateTime<Utc>>)
        .transpose()?;
    ensure!(
        target_case_clock_matches(witness.metadata.surface, &witness.metadata.clocks, clock),
        "protected Target Case clock differs from the current Replay report"
    );
    Ok(())
}

fn target_case_clock_matches(
    surface: Surface,
    clocks: &WitnessClocks,
    started: Option<DateTime<Utc>>,
) -> bool {
    clocks.case.target == started
        // Case admission can precede request_begin. The independently observed
        // dependency clock proves why the primary clock was absent at capture.
        || surface == Surface::DependencyRequest
            && clocks.case.target.is_none()
            && clocks.dependency.target.zip(started).is_some_and(|(observed, start)| observed < start)
}

#[derive(Serialize, Deserialize)]
struct ProtectedPayload {
    source: String,
    target: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    id: String,
    metadata: WitnessMetadata,
    encrypted: String,
}

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn label(id: &str, metadata: &WitnessMetadata) -> Result<String> {
    Ok(format!(
        "traffic-policy-witness/v1:{id}:{}",
        serde_json::to_string(metadata)?
    ))
}

pub fn artifact_path(report: &Path, manifest: &WitnessManifest) -> Result<PathBuf> {
    let name = Path::new(&manifest.artifact);
    ensure!(
        name.components().count() == 1
            && matches!(
                name.components().next(),
                Some(std::path::Component::Normal(_))
            )
            && manifest.artifact.starts_with("policy-witnesses-")
            && manifest.artifact.ends_with(".jsonl"),
        "invalid policy witness artifact reference"
    );
    Ok(report
        .parent()
        .context("Replay report has no parent")?
        .join(name))
}

pub fn verify(report: &Path, manifest: &WitnessManifest) -> Result<PathBuf> {
    if matches!(manifest.version, 2..=4) {
        return v2::verify(report, manifest);
    }
    ensure!(
        manifest.version == 1
            && manifest.sealed
            && manifest.complete
            && manifest.omitted == 0
            && manifest.observed == manifest.recorded
            && manifest.recorded == manifest.witnesses.len(),
        "policy payload coverage is incomplete; run fresh genuine Replay before planning"
    );
    let path = artifact_path(report, manifest)?;
    let metadata = std::fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= 64 * 1024 * 1024,
        "policy witness artifact must be a regular file"
    );
    let bytes = std::fs::read(&path)?;
    ensure!(
        digest(&bytes) == manifest.sha256,
        "policy witness artifact changed after publication"
    );
    let mut offset = 0_u64;
    let mut ids = std::collections::BTreeSet::new();
    for witness in &manifest.witnesses {
        ensure!(
            witness.length <= 4 * 1024 * 1024
                && witness.offset == offset
                && ids.insert(&witness.id),
            "policy witness index is incomplete or duplicated"
        );
        offset = offset
            .checked_add(witness.length)
            .context("policy witness index overflow")?;
    }
    ensure!(
        offset == u64::try_from(bytes.len())?,
        "policy witness index does not cover its complete artifact"
    );
    Ok(path)
}

pub fn read(
    path: &Path,
    witness: &WitnessRef,
    key_context: &Path,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    if let Some(proof) = &witness.proof {
        return v2::read(path, witness, proof, key_context);
    }
    use std::io::{Read, Seek, SeekFrom};
    ensure!(
        witness.length <= 4 * 1024 * 1024,
        "policy witness exceeds the supported bound"
    );
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(witness.offset))?;
    let mut bytes = vec![0; usize::try_from(witness.length)?];
    file.read_exact(&mut bytes)?;
    ensure!(
        digest(&bytes) == witness.sha256,
        "protected policy witness changed"
    );
    let envelope: Envelope = serde_json::from_slice(&bytes)?;
    ensure!(
        envelope.id == witness.id && envelope.metadata == witness.metadata,
        "policy witness metadata differs"
    );
    let payload = crate::request_headers::decrypt_evidence(
        key_context,
        &label(&envelope.id, &envelope.metadata)?,
        &envelope.encrypted,
    )?;
    let payload: ProtectedPayload = serde_json::from_slice(&payload)?;
    let source = STANDARD.decode(payload.source)?;
    let target = payload.target.map(|b| STANDARD.decode(b)).transpose()?;
    witness.metadata.validate_roles(target.is_some())?;
    ensure!(
        digest(&source) == witness.source_sha256
            && target.as_ref().map(|b| digest(b)) == witness.target_sha256,
        "policy witness plaintext fingerprint differs"
    );
    Ok((source, target))
}

#[cfg(test)]
mod tests;
