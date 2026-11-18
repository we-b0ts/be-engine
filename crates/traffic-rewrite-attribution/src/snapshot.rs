//! One authenticated ownership identity for status receipts and actual Replay.
use super::{
    decisions::{DecisionSet, DecisionTemplate},
    rules, source,
};
use crate::{
    dependency::attribution::{AttributionDecision, DependencyOwner},
    model::RewriteState,
};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, path::Path};

struct Current {
    decisions: DecisionSet,
    source_revision: Option<String>,
    inventory: String,
    rules: BTreeMap<String, String>,
    case_defaults: BTreeMap<uuid::Uuid, DependencyOwner>,
}
impl Current {
    fn eligible(&self, decision: &DecisionTemplate) -> bool {
        Some(decision.proof.source_revision.as_str()) == self.source_revision.as_deref()
            && rules::current(decision, &self.rules)
    }
    fn identity(&self, run: &str) -> Result<String> {
        let identity = self.decisions.snapshot(
            run,
            self.source_revision.as_deref(),
            &self.inventory,
            |decision| self.eligible(decision),
        )?;
        if self.case_defaults.is_empty() {
            return Ok(identity);
        }
        Ok(crate::policy_evidence::digest(&serde_json::to_vec(&(
            "case-window-notification-ownership/v1",
            identity,
            &self.case_defaults,
        ))?))
    }
    fn expand(&self) -> Vec<AttributionDecision> {
        let mut values = self
            .decisions
            .iter()
            .filter(|(_, decision)| self.eligible(decision))
            .map(|(id, decision)| decision.decision(*id))
            .collect::<Vec<_>>();
        values.sort_unstable_by_key(|decision| decision.exchange_id);
        values
    }
}

pub type SnapshotReader = fn(&Path) -> Result<Option<RewriteState>>;

fn current(
    read_snapshot: SnapshotReader,
    target: Option<&Path>,
    explicit_source: Option<&Path>,
    run: &str,
) -> Result<Current> {
    let mut state = target
        .map(read_snapshot)
        .transpose()?
        .flatten()
        .filter(|state| state.recording_run_id == run);
    let fallback = target.map(|root| {
        root.join(crate::repository::LOCAL_ARTIFACTS_ROOT)
            .join("recordings")
            .join(run)
    });
    let source_path = explicit_source
        .or_else(|| {
            state
                .as_ref()
                .and_then(|state| state.case_source.as_deref())
        })
        .or(fallback.as_deref())
        .context("ownership snapshot has no current Source recording")?;
    let inventory = source::inventory_at(source_path, run)?.0;
    let case_defaults = super::case_defaults::load(source_path, target)?;
    let source_revision = state
        .as_ref()
        .and_then(|state| state.source_revision.clone());
    let decisions = if let Some(state) = state
        .as_mut()
        .filter(|state| state.dependency_review.recording_run_id.as_deref() == Some(run))
    {
        ensure!(
            state.dependency_review.source_inventory_id.as_deref() == Some(&inventory),
            "attribution overlay belongs to a changed sealed Source inventory; obtain fresh independent proof"
        );
        std::mem::take(&mut state.dependency_review.decisions)
    } else {
        DecisionSet::default()
    };
    let rules = if decisions.is_empty() {
        BTreeMap::new()
    } else {
        rules::fingerprints(&rules::load(
            target.context("owned Source overlay requires its workflow target")?,
        )?)?
    };
    Ok(Current {
        decisions,
        source_revision,
        inventory,
        rules,
        case_defaults,
    })
}

pub fn identity(read_snapshot: SnapshotReader, target: &Path, run: &str) -> Result<String> {
    current(read_snapshot, Some(target), None, run)?.identity(run)
}

pub fn identity_for_source(
    read_snapshot: SnapshotReader,
    target: &Path,
    source: &Path,
    run: &str,
) -> Result<String> {
    current(read_snapshot, Some(target), Some(source), run)?.identity(run)
}

#[cfg(any(test, feature = "test-support"))]
pub fn overlay(
    read_snapshot: SnapshotReader,
    target: &Path,
    run: &str,
) -> Result<Vec<AttributionDecision>> {
    Ok(current(read_snapshot, Some(target), None, run)?.expand())
}

pub fn frozen(
    read_snapshot: SnapshotReader,
    target: Option<&Path>,
    source: &Path,
    run: &str,
) -> Result<(BTreeMap<uuid::Uuid, DependencyOwner>, String)> {
    let current = current(read_snapshot, target, Some(source), run)?;
    let identity = current.identity(run)?;
    let mut owners = current.case_defaults.clone();
    for decision in current.expand() {
        owners.insert(decision.exchange_id, decision.owner);
    }
    Ok((owners, identity))
}
