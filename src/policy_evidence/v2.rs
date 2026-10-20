//! Independently identified observations, shared encrypted payloads and signed
//! candidate associations. Content equality shares storage, never request identity.
use super::*;
use hmac::{Hmac, Mac};
use std::collections::BTreeSet;

mod reader;
pub(crate) use reader::read_target;
pub(super) use reader::{read, verify};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct TargetMetadata {
    pub case_id: String,
    pub surface: Surface,
    pub role: TargetRole,
    pub resource: Option<Resource>,
    pub operation: String,
    pub clocks: WitnessClocks,
}
impl TargetMetadata {
    pub(crate) fn from_pair(metadata: &WitnessMetadata) -> Self {
        let mut clocks = metadata.clocks.clone();
        for pair in [
            &mut clocks.case,
            &mut clocks.dependency,
            &mut clocks.delivery,
        ] {
            pair.source = None;
        }
        Self {
            case_id: metadata.source.case_id.clone(),
            surface: metadata.surface,
            role: metadata.target_role,
            resource: metadata.resource.clone(),
            operation: metadata.operation.clone(),
            clocks,
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            !self.case_id.is_empty(),
            "Target observation requires a Case identity"
        );
        let expected = if self.surface == Surface::DependencyResponse {
            TargetRole::DerivedDelivery
        } else {
            TargetRole::IndependentTargetObservation
        };
        ensure!(
            self.role == expected,
            "derived delivery cannot become independent Target proof"
        );
        ensure!(
            [
                &self.clocks.case,
                &self.clocks.dependency,
                &self.clocks.delivery
            ]
            .into_iter()
            .all(|pair| pair.source.is_none()),
            "Target observation borrowed Source clocks"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct BlobRef {
    pub id: String,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
    pub plaintext_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) source: Option<super::source::SourcePayload>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) chunks: Vec<super::storage::Chunk>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SourceObservation {
    pub id: String,
    pub metadata: WitnessMetadata,
    pub blob: usize,
    pub authentication: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct TargetObservation {
    pub id: String,
    pub metadata: TargetMetadata,
    pub blob: usize,
    pub authentication: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CandidateAssociation {
    pub source: usize,
    pub target: usize,
    pub authentication: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CandidateGroup {
    pub target: usize,
    pub sources: Vec<usize>,
    pub authentication: String,
}
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct ObservationGraph {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayBinding>,
    pub session_id: String,
    pub key_envelope: String,
    pub blobs: Vec<BlobRef>,
    pub sources: Vec<SourceObservation>,
    pub targets: Vec<TargetObservation>,
    pub associations: Vec<CandidateAssociation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<CandidateGroup>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) segments: Vec<super::storage::Segment>,
    pub payload_bytes: usize,
    pub association_attempts: usize,
    pub authentication: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ReplayBinding {
    pub session_id: String,
    pub policy_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct PairProof {
    session_id: String,
    key_envelope: String,
    source: SourceObservation,
    source_blob: BlobRef,
    target: Option<(TargetObservation, BlobRef)>,
    association: Option<AssociationProof>,
}
#[derive(Debug, Clone, PartialEq)]
pub(super) enum AssociationProof {
    Pair(String),
    Group {
        target: String,
        sources: Vec<String>,
        authentication: String,
    },
}

#[derive(Serialize, Deserialize)]
pub(super) struct BlobEnvelope {
    pub id: String,
    pub encrypted: String,
}

pub(super) fn sign<T: Serialize>(key: &[u8], domain: &str, value: &T) -> Result<String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid observation signing key"))?;
    mac.update(domain.as_bytes());
    mac.update(&[0]);
    mac.update(&serde_json::to_vec(value)?);
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}
pub(super) fn authenticate<T: Serialize>(
    key: &[u8],
    domain: &str,
    value: &T,
    signature: &str,
) -> Result<()> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid observation signing key"))?;
    mac.update(domain.as_bytes());
    mac.update(&[0]);
    mac.update(&serde_json::to_vec(value)?);
    mac.verify_slice(&STANDARD.decode(signature)?)
        .map_err(|_| anyhow::anyhow!("policy observation authentication failed"))
}
pub(super) fn key_label(session_id: &str) -> String {
    format!("traffic-policy-observation-key/v2:{session_id}")
}
pub(super) fn blob_label(session_id: &str, id: &str) -> String {
    format!("traffic-policy-blob/v2:{session_id}:{id}")
}
pub(super) fn source_metadata(metadata: &WitnessMetadata) -> WitnessMetadata {
    let mut metadata = metadata.clone();
    metadata.target_role = TargetRole::Unavailable;
    for pair in [
        &mut metadata.clocks.case,
        &mut metadata.clocks.dependency,
        &mut metadata.clocks.delivery,
    ] {
        pair.target = None;
    }
    if metadata.surface == Surface::DependencyRequest {
        metadata.clocks.delivery.source = None;
    }
    if let Some(resource) = &mut metadata.resource {
        resource.endpoint.host.make_ascii_lowercase();
    }
    metadata
}
pub(super) fn source_key(metadata: &WitnessMetadata) -> Result<Option<String>> {
    let identified = metadata.surface == Surface::ApiResponse
        || metadata
            .source
            .exchange_id
            .as_ref()
            .is_some_and(|id| !id.is_empty())
        || metadata.source.connection_id.is_some() && metadata.source.sequence.is_some();
    Ok(identified
        .then(|| serde_json::to_vec(&source_metadata(metadata)).map(|bytes| digest(&bytes)))
        .transpose()?)
}

pub(super) fn compatible(source: &WitnessMetadata, target: &TargetMetadata) -> bool {
    if source.source.case_id != target.case_id || source.surface != target.surface {
        return false;
    }
    let resource = match (&source.resource, &target.resource) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.protocol == right.protocol
                && left
                    .endpoint
                    .host
                    .eq_ignore_ascii_case(&right.endpoint.host)
                && left.endpoint.port == right.endpoint.port
                && left.database == right.database
                && left.username == right.username
        }
        _ => false,
    };
    resource
        && (source.operation.eq_ignore_ascii_case(&target.operation)
            || source
                .resource
                .as_ref()
                .is_some_and(|resource| resource.protocol == crate::policy::Protocol::Mysql)
                && [source.operation.as_str(), target.operation.as_str()]
                    .into_iter()
                    .all(|operation| {
                        operation.eq_ignore_ascii_case("COM_QUERY")
                            || operation.eq_ignore_ascii_case("COM_STMT_EXECUTE")
                    }))
}

impl ObservationGraph {
    pub(super) fn pair(
        &self,
        source: usize,
        association: Option<&CandidateAssociation>,
    ) -> Result<WitnessRef> {
        let source = self
            .sources
            .get(source)
            .context("Source observation reference is missing")?
            .clone();
        let source_blob = self
            .blobs
            .get(source.blob)
            .context("Source payload reference is missing")?
            .clone();
        let target = association
            .map(|link| -> Result<_> {
                let target = self
                    .targets
                    .get(link.target)
                    .context("Target observation reference is missing")?
                    .clone();
                let blob = self
                    .blobs
                    .get(target.blob)
                    .context("Target payload reference is missing")?
                    .clone();
                Ok((target, blob))
            })
            .transpose()?;
        let mut metadata = source.metadata.clone();
        if let Some((target, _)) = &target {
            ensure!(
                compatible(&metadata, &target.metadata),
                "candidate association crosses Case, surface, resource or operation"
            );
            metadata.target_role = target.metadata.role;
            metadata.clocks.case.target = target.metadata.clocks.case.target;
            metadata.clocks.dependency.target = target.metadata.clocks.dependency.target;
            metadata.clocks.delivery.target = target.metadata.clocks.delivery.target;
        }
        let id = target.as_ref().map_or_else(
            || source.id.clone(),
            |(target, _)| format!("{}:{}", source.id, target.id),
        );
        Ok(WitnessRef {
            id,
            metadata,
            offset: source_blob.offset,
            length: source_blob.length,
            sha256: source_blob.sha256.clone(),
            source_sha256: source_blob.id.clone(),
            target_sha256: target.as_ref().map(|(_, blob)| blob.id.clone()),
            target_observation_id: target.as_ref().map(|(target, _)| target.id.clone()),
            proof: Some(Box::new(PairProof {
                session_id: self.session_id.clone(),
                key_envelope: self.key_envelope.clone(),
                source,
                source_blob,
                target,
                association: association
                    .map(|link| AssociationProof::Pair(link.authentication.clone())),
            })),
        })
    }
    pub(super) fn pair_group(&self, source: usize, group: &CandidateGroup) -> Result<WitnessRef> {
        ensure!(
            group.sources.contains(&source),
            "Source is outside candidate coverage"
        );
        let mut witness = self.pair(
            source,
            Some(&CandidateAssociation {
                source,
                target: group.target,
                authentication: String::new(),
            }),
        )?;
        witness.proof.as_mut().unwrap().association = Some(AssociationProof::Group {
            target: self
                .targets
                .get(group.target)
                .context("candidate Target missing")?
                .id
                .clone(),
            sources: self.group_sources(group)?,
            authentication: group.authentication.clone(),
        });
        Ok(witness)
    }
    pub(super) fn group_sources(&self, group: &CandidateGroup) -> Result<Vec<String>> {
        group
            .sources
            .iter()
            .map(|index| {
                Ok(self
                    .sources
                    .get(*index)
                    .context("candidate Source missing")?
                    .id
                    .clone())
            })
            .collect()
    }
    pub(super) fn key(&self, context: &Path) -> Result<Vec<u8>> {
        let key = crate::request_headers::decrypt_evidence(
            context,
            &key_label(&self.session_id),
            &self.key_envelope,
        )?;
        ensure!(key.len() == 32, "invalid observation session signing key");
        Ok(key)
    }
    pub(super) fn validate(&self, key: &[u8]) -> Result<()> {
        let mut ids = BTreeSet::new();
        for source in &self.sources {
            ensure!(
                ids.insert(&source.id) && source.metadata == source_metadata(&source.metadata),
                "invalid Source observation identity or clocks"
            );
            source.metadata.validate_roles(false)?;
            let blob = self
                .blobs
                .get(source.blob)
                .context("Source observation payload is missing")?;
            authenticate(
                key,
                "source",
                &(&self.session_id, &source.id, &source.metadata, blob),
                &source.authentication,
            )?;
        }
        ids.clear();
        for target in &self.targets {
            ensure!(
                ids.insert(&target.id),
                "duplicate Target observation identity"
            );
            target.metadata.validate()?;
            let blob = self
                .blobs
                .get(target.blob)
                .context("Target observation payload is missing")?;
            ensure!(
                blob.source.is_none(),
                "Target observation cannot borrow a Source payload reference"
            );
            authenticate(
                key,
                "target",
                &(&self.session_id, &target.id, &target.metadata, blob),
                &target.authentication,
            )?;
        }
        let mut associations = BTreeSet::new();
        for association in &self.associations {
            ensure!(
                associations.insert((association.source, association.target)),
                "duplicate candidate association"
            );
            let source = self
                .sources
                .get(association.source)
                .context("candidate Source observation is missing")?;
            let target = self
                .targets
                .get(association.target)
                .context("candidate Target observation is missing")?;
            ensure!(
                compatible(&source.metadata, &target.metadata),
                "candidate association crosses Case, surface, resource or operation"
            );
            authenticate(
                key,
                "association",
                &(&self.session_id, &source.id, &target.id),
                &association.authentication,
            )?;
        }
        for group in &self.groups {
            let target = self
                .targets
                .get(group.target)
                .context("candidate Target missing")?;
            ensure!(!group.sources.is_empty(), "empty candidate coverage group");
            for index in &group.sources {
                let source = self
                    .sources
                    .get(*index)
                    .context("candidate Source missing")?;
                ensure!(
                    associations.insert((*index, group.target))
                        && compatible(&source.metadata, &target.metadata),
                    "duplicate or incompatible candidate coverage"
                );
            }
            authenticate(
                key,
                "candidate-group",
                &(&self.session_id, &target.id, self.group_sources(group)?),
                &group.authentication,
            )?;
        }
        Ok(())
    }
}

pub(super) fn manifest_signature(manifest: &WitnessManifest, key: &[u8]) -> Result<String> {
    let mut manifest = manifest.clone();
    if manifest.version == 4 {
        manifest.authentication.clear();
    } else {
        manifest
            .observations
            .as_mut()
            .context("missing observation graph")?
            .authentication
            .clear();
    }
    sign(key, "manifest", &manifest)
}
