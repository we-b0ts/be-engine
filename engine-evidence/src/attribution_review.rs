//! Diagnostic Source projections over the unattributed scope of a sealed recording.
mod grouping;
mod mysql;

use crate::dependency::observation::CaptureMetadata;
use crate::dependency_index::{RecordStream, recording};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};
use traffic_protocol::evidence::EvidenceRegistry;
use uuid::Uuid;

pub struct Admission {
    pub captured: BTreeSet<Uuid>,
    pub optional_controls: BTreeSet<Uuid>,
}

pub fn admission(source: &Path) -> Result<Admission> {
    read_admission(
        source,
        true,
        crate::protocols::default_providers().evidence(),
    )
}

fn read_admission(
    source: &Path,
    authenticate: bool,
    evidence: &EvidenceRegistry,
) -> Result<Admission> {
    let mut captured = BTreeSet::new();
    let mut repeated = BTreeSet::new();
    let mut mysql = mysql::Source::default();
    visit(source, authenticate, |event| {
        if let Some(capture) = pending_capture(&event)?
            && !captured.insert(capture.exchange_id)
        {
            repeated.insert(capture.exchange_id);
        }
        mysql.observe(event, evidence);
        Ok(())
    })?;
    Ok(Admission {
        optional_controls: mysql
            .optional_controls()
            .difference(&repeated)
            .copied()
            .collect(),
        captured,
    })
}

/// Replay uses the same Source proof on the already selected recording,
/// with structural bounds from the streaming reader.
pub fn optional_controls_for_replay(
    source: &Path,
    evidence: &EvidenceRegistry,
) -> Result<BTreeSet<Uuid>> {
    Ok(read_admission(source, false, evidence)?.optional_controls)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct GroupShape {
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    operation: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    selectors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector_count: Option<usize>,
}

pub struct Group {
    pub id: String,
    pub shape: GroupShape,
    pub members: Vec<Uuid>,
}

/// Grouping is a navigation aid. Membership is still verified against the
/// sealed capture and applicable ownership rules when a decision is submitted.
pub fn groups(source: &Path, pending: &BTreeSet<Uuid>) -> Result<Vec<Group>> {
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    let mut members = Vec::new();
    let mut mysql = mysql::Source::default();
    let providers = crate::protocols::default_providers();
    visit(source, true, |event| {
        if let Some(capture) = pending_capture(&event)?
            && pending.contains(&capture.exchange_id)
        {
            members.push((capture.exchange_id, grouping::shape(&event, &capture)));
        }
        mysql.observe(event, providers.evidence());
        Ok(())
    })?;
    let transactions = mysql.transaction_shapes(pending);
    let mut grouped = BTreeMap::<Arc<GroupShape>, Vec<Uuid>>::new();
    let mut represented = BTreeSet::new();
    for (id, shape) in members {
        if !represented.insert(id) {
            continue;
        }
        let shape = transactions
            .get(&id)
            .cloned()
            .unwrap_or_else(|| Arc::new(shape));
        grouped.entry(shape).or_default().push(id);
    }
    ensure!(
        represented == *pending,
        "unattributed review does not match the sealed Source scope"
    );
    let mut groups = grouped
        .into_iter()
        .map(|(shape, members)| {
            let id = crate::policy_evidence::digest(&serde_json::to_vec(&(
                "source-attribution-group/v1",
                shape.as_ref(),
            ))?);
            let mut shape = (*shape).clone();
            const SELECTOR_SAMPLES: usize = 8;
            if shape.selectors.len() > SELECTOR_SAMPLES {
                shape.selector_count = Some(shape.selectors.len());
                shape.selectors.truncate(SELECTOR_SAMPLES);
            }
            Ok(Group { id, shape, members })
        })
        .collect::<Result<Vec<_>>>()?;
    groups.sort_by(|a, b| {
        b.members
            .len()
            .cmp(&a.members.len())
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(groups)
}

fn pending_capture(event: &Value) -> Result<Option<CaptureMetadata>> {
    let capture: CaptureMetadata = serde_json::from_value(event["capture"].clone())?;
    Ok(needs_review(&capture).then_some(capture))
}

fn needs_review(capture: &CaptureMetadata) -> bool {
    capture.semantic_required
        && matches!(
            capture.attribution,
            crate::dependency::attribution::DependencyOwner::Unattributed { .. }
        )
}

fn visit(
    source: &Path,
    authenticate: bool,
    mut visitor: impl FnMut(Value) -> Result<()>,
) -> Result<()> {
    let (root, manifest) = recording::manifest(source)?;
    if manifest.semantic_inventory.unattributed_dependencies == 0 {
        return Ok(());
    }
    let scope = root.join("indexes/unattributed-scope.json");
    let mut stream = if authenticate {
        recording::authenticate(&root)?;
        RecordStream::open(&scope)?
    } else {
        RecordStream::open_for_replay(&scope)?
    };
    while let Some((_, bytes)) = stream.next()? {
        if !bytes.iter().all(u8::is_ascii_whitespace) {
            visitor(serde_json::from_slice(bytes).context("invalid unattributed Source event")?)?;
        }
    }
    Ok(())
}
