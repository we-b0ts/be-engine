//! Select compact authenticated identities before expanding one requested pair.
use std::collections::BTreeSet;

use super::*;
use crate::policy::{Protocol, Resource, Surface};
use crate::policy_evidence::{SourceIdentity, TargetRole, WitnessEntry};

pub enum Candidate<'a> {
    Witness(WitnessEntry<'a>),
    Target { index: usize, id: &'a str },
}

impl Candidate<'_> {
    pub fn source_identity(&self) -> Option<&SourceIdentity> {
        match self {
            Self::Witness(entry) => Some(&entry.metadata().source),
            Self::Target { .. } => None,
        }
    }
    pub fn target_id(&self) -> Option<&str> {
        match self {
            Self::Witness(entry) => entry.target_observation_id(),
            Self::Target { id, .. } => Some(id),
        }
    }
    pub fn association(&self) -> &'static str {
        match self {
            Self::Witness(entry) if entry.has_target() => "authenticated_runtime_candidate",
            Self::Witness(_) => "source_only_target_unavailable",
            Self::Target { .. } => "independent_target_without_source_candidate",
        }
    }
    pub fn read(&self, dataset: &Dataset<'_>) -> Result<(Option<Value>, Option<Value>)> {
        let context = dataset.case_dir(dataset.event_case(self)?)?;
        let path = dataset
            .private
            .as_deref()
            .context("private payload artifact is missing")?;
        match self {
            Self::Witness(entry) => {
                let witness = entry.expand()?;
                policy_evidence::verify_case_clock(&witness, &dataset.report)?;
                let (source, target) = policy_evidence::read(path, &witness, &context)?;
                Ok((
                    Some(envelope(&source)?),
                    target.as_deref().map(envelope).transpose()?,
                ))
            }
            Self::Target { index, .. } => {
                let bytes = policy_evidence::read_target(
                    path,
                    dataset.manifest.as_ref().unwrap(),
                    *index,
                    &context,
                )?;
                Ok((None, Some(envelope(&bytes)?)))
            }
        }
    }
}

impl Dataset<'_> {
    fn event_case<'a>(&'a self, candidate: &'a Candidate<'_>) -> Result<&'a str> {
        match candidate {
            Candidate::Witness(entry) => Ok(&entry.metadata().source.case_id),
            Candidate::Target { index, .. } => Ok(&self
                .manifest
                .as_ref()
                .unwrap()
                .graph()
                .context("Target observation graph is missing")?
                .targets[*index]
                .metadata
                .case_id),
        }
    }

    pub fn observations(&self, failure: usize) -> Result<Vec<Candidate<'_>>> {
        let event = self.event(failure)?;
        let manifest = self
            .manifest
            .as_ref()
            .context("protected evidence is unavailable")?;
        let path = self
            .private
            .as_deref()
            .context("private payload artifact is missing")?;
        let context = self.case_dir(event["case_id"].as_str().context("failure has no Case")?)?;
        let exact = event["target_observation_id"].as_str();
        let mut targets = BTreeSet::new();
        let mut target_indices = Vec::new();
        if let Some(graph) = manifest.graph() {
            for (index, target) in graph.targets.iter().enumerate() {
                if target.metadata.surface != Surface::DependencyRequest
                    || target.metadata.role != TargetRole::IndependentTargetObservation
                    || target.metadata.case_id != event["case_id"].as_str().unwrap_or_default()
                    || !matches(&target.metadata.resource, &target.metadata.operation, event)
                    || exact.is_some_and(|id| id != target.id)
                {
                    continue;
                }
                let bytes = policy_evidence::read_target(path, manifest, index, &context)?;
                if same_path(&envelope(&bytes)?, event) {
                    targets.insert(target.id.as_str());
                    target_indices.push((index, target.id.as_str()));
                }
            }
        }
        let mut candidates = Vec::new();
        let mut associated = BTreeSet::new();
        let mut source_only = Vec::new();
        for entry in manifest.witness_entries()? {
            let entry = entry?;
            let metadata = entry.metadata();
            if metadata.surface != Surface::DependencyRequest
                || metadata.source.case_id != event["case_id"].as_str().unwrap_or_default()
                || !matches(&metadata.resource, &metadata.operation, event)
            {
                continue;
            }
            if entry.has_target() {
                if manifest.graph().is_some() {
                    if entry
                        .target_observation_id()
                        .is_none_or(|id| !targets.contains(id))
                    {
                        continue;
                    }
                } else {
                    // Legacy pairs lack a graph. Retain their association ambiguity.
                    let pair = Candidate::Witness(entry);
                    let (_, target) = pair.read(self)?;
                    if target
                        .as_ref()
                        .is_none_or(|target| !same_path(target, event))
                    {
                        continue;
                    }
                }
                if let Some(id) = entry.target_observation_id() {
                    associated.insert(id);
                }
                candidates.push(Candidate::Witness(entry));
            } else {
                source_only.push(entry);
            }
        }
        for (index, id) in target_indices {
            if !associated.contains(id) {
                candidates.push(Candidate::Target { index, id });
            }
        }
        if candidates.is_empty() {
            for entry in source_only {
                let pair = Candidate::Witness(entry);
                let (source, _) = pair.read(self)?;
                if source
                    .as_ref()
                    .is_some_and(|source| same_path(source, event))
                {
                    candidates.push(pair);
                }
            }
        }
        Ok(candidates)
    }
}

fn envelope(bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes)?;
    ensure!(
        value["protocol"] == "http",
        "protected request is not an HTTP envelope"
    );
    Ok(value)
}

fn matches(resource: &Option<Resource>, operation: &str, event: &Value) -> bool {
    resource.as_ref().is_some_and(|resource| {
        resource.protocol == Protocol::Http
            && event["target"]["host"]
                .as_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(&resource.endpoint.host))
            && event["target"]["port"].as_u64() == Some(resource.endpoint.port.into())
    }) && event["method"]
        .as_str()
        .is_some_and(|method| method.eq_ignore_ascii_case(operation))
}

fn same_path(envelope: &Value, event: &Value) -> bool {
    envelope["uri"]
        .as_str()
        .is_some_and(|uri| traffic_protocol_http::uri::uri_path_only(uri) == event["uri"])
        && envelope["scheme"] == event["scheme"]
}
