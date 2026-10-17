//! Borrow compact inventory metadata; expand proofs only after selection.
use super::v2::{CandidateAssociation, SourceObservation};
use super::*;
use std::borrow::Cow;

pub(crate) struct WitnessEntries<'a> {
    legacy: std::slice::Iter<'a, WitnessRef>,
    graph: Option<&'a ObservationGraph>,
    association: usize,
    source: usize,
}

pub(crate) enum WitnessEntry<'a> {
    Legacy(&'a WitnessRef),
    Observation {
        graph: &'a ObservationGraph,
        source_index: usize,
        source: &'a SourceObservation,
        association: Option<&'a CandidateAssociation>,
    },
}

impl<'a> WitnessEntries<'a> {
    pub(super) fn new(manifest: &'a WitnessManifest) -> Result<Self> {
        let graph = if manifest.version == 2 {
            Some(
                manifest
                    .observations
                    .as_ref()
                    .context("missing observation graph")?,
            )
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
                    }),
            );
        }
        let source_index = self.source;
        let source = graph.sources.get(source_index)?;
        self.source += 1;
        Some(Ok(WitnessEntry::Observation {
            graph,
            source_index,
            source,
            association: None,
        }))
    }
}

impl<'a> WitnessEntry<'a> {
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
            Self::Observation { association, .. } => association.is_some(),
        }
    }

    pub(crate) fn expand(self) -> Result<Cow<'a, WitnessRef>> {
        match self {
            Self::Legacy(witness) => Ok(Cow::Borrowed(witness)),
            Self::Observation {
                graph,
                source_index,
                association,
                ..
            } => graph.pair(source_index, association).map(Cow::Owned),
        }
    }
}
