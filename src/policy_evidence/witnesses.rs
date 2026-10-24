//! Borrow compact inventory metadata; expand proofs only after selection.
use super::v2::{CandidateAssociation, CandidateGroup, SourceObservation};
use super::*;
use std::borrow::Cow;

pub(crate) struct WitnessEntries<'a> {
    legacy: std::slice::Iter<'a, WitnessRef>,
    graph: Option<&'a ObservationGraph>,
    association: usize,
    source: usize,
    group: usize,
    member: usize,
}

#[derive(Clone, Copy)]
pub(crate) enum WitnessEntry<'a> {
    Legacy(&'a WitnessRef),
    Observation {
        graph: &'a ObservationGraph,
        source_index: usize,
        source: &'a SourceObservation,
        association: Option<&'a CandidateAssociation>,
        group: Option<&'a CandidateGroup>,
    },
}

pub(crate) struct WitnessIndex<'a> {
    entries: std::collections::BTreeMap<(Surface, SourceIdentity), Vec<WitnessEntry<'a>>>,
}
impl<'a> WitnessIndex<'a> {
    pub(super) fn new(manifest: &'a WitnessManifest) -> Result<Self> {
        let mut entries = std::collections::BTreeMap::<_, Vec<_>>::new();
        for entry in manifest.witness_entries()? {
            let entry = entry?;
            if entry.has_target() {
                let metadata = entry.metadata();
                entries
                    .entry((metadata.surface, metadata.source.clone()))
                    .or_default()
                    .push(entry);
            }
        }
        Ok(Self { entries })
    }
    pub(crate) fn for_source(
        &self,
        surface: Surface,
        source: &SourceIdentity,
    ) -> impl Iterator<Item = WitnessEntry<'a>> + '_ {
        self.entries
            .get(&(surface, source.clone()))
            .into_iter()
            .flatten()
            .copied()
    }
}

impl<'a> WitnessEntries<'a> {
    pub(super) fn new(manifest: &'a WitnessManifest) -> Result<Self> {
        let graph = if matches!(manifest.version, 2..=4) {
            Some(manifest.graph().context("missing observation graph")?)
        } else {
            None
        };
        Ok(Self {
            legacy: if graph.is_some() {
                [].iter()
            } else {
                manifest.witnesses.iter()
            },
            graph,
            association: 0,
            source: 0,
            group: 0,
            member: 0,
        })
    }
}

impl<'a> Iterator for WitnessEntries<'a> {
    type Item = Result<WitnessEntry<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(graph) = self.graph else {
            return self
                .legacy
                .next()
                .map(|witness| Ok(WitnessEntry::Legacy(witness)));
        };
        // Keep the original ordering: candidates first, then Source-only inventory.
        if let Some(association) = graph.associations.get(self.association) {
            self.association += 1;
            return Some(
                graph
                    .sources
                    .get(association.source)
                    .context("Source observation reference is missing")
                    .map(|source| WitnessEntry::Observation {
                        graph,
                        source_index: association.source,
                        source,
                        association: Some(association),
                        group: None,
                    }),
            );
        }
        while let Some(group) = graph.groups.get(self.group) {
            if let Some(index) = group.sources.get(self.member).copied() {
                self.member += 1;
                return Some(
                    graph
                        .sources
                        .get(index)
                        .context("candidate Source missing")
                        .map(|source| WitnessEntry::Observation {
                            graph,
                            source_index: index,
                            source,
                            association: None,
                            group: Some(group),
                        }),
                );
            }
            self.group += 1;
            self.member = 0;
        }
        let source_index = self.source;
        let source = graph.sources.get(source_index)?;
        self.source += 1;
        Some(Ok(WitnessEntry::Observation {
            graph,
            source_index,
            source,
            association: None,
            group: None,
        }))
    }
}

impl<'a> WitnessEntry<'a> {
    /// Canonical Source metadata deliberately carries no Target role. Read the
    /// paired observation without expanding its complete protected payload.
    pub(crate) fn target_role(&self) -> TargetRole {
        match self {
            Self::Legacy(witness) => witness.metadata.target_role,
            Self::Observation {
                graph,
                association,
                group,
                ..
            } => association
                .map(|link| link.target)
                .or_else(|| group.map(|group| group.target))
                .and_then(|index| graph.targets.get(index))
                .map_or(TargetRole::Unavailable, |target| target.metadata.role),
        }
    }

    pub(crate) fn target_observation_id(&self) -> Option<&'a str> {
        match self {
            Self::Legacy(witness) => witness.target_observation_id.as_deref(),
            Self::Observation {
                graph,
                association,
                group,
                ..
            } => {
                let index = association
                    .map(|a| a.target)
                    .or_else(|| group.map(|g| g.target))?;
                graph.targets.get(index).map(|target| target.id.as_str())
            }
        }
    }

    pub(crate) fn metadata(&self) -> &WitnessMetadata {
        match self {
            Self::Legacy(witness) => &witness.metadata,
            Self::Observation { source, .. } => &source.metadata,
        }
    }

    pub(crate) fn source_sha256(&self) -> Result<&str> {
        match self {
            Self::Legacy(witness) => Ok(&witness.source_sha256),
            Self::Observation { graph, source, .. } => Ok(&graph
                .blobs
                .get(source.blob)
                .context("Source payload reference is missing")?
                .id),
        }
    }

    pub(crate) fn has_target(&self) -> bool {
        match self {
            Self::Legacy(witness) => witness.target_sha256.is_some(),
            Self::Observation {
                association, group, ..
            } => association.is_some() || group.is_some(),
        }
    }

    pub(crate) fn expand(self) -> Result<Cow<'a, WitnessRef>> {
        match self {
            Self::Legacy(witness) => Ok(Cow::Borrowed(witness)),
            Self::Observation {
                graph,
                source_index,
                association,
                group,
                ..
            } => if let Some(group) = group {
                graph.pair_group(source_index, group)
            } else {
                graph.pair(source_index, association)
            }
            .map(Cow::Owned),
        }
    }
}
