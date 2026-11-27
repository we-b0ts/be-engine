//! Whole-window confirmation and candidate coverage.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{Candidate, Workflow};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Confirmation {
    pub group: String,
    pub assignment_id: Uuid,
    pub sequences: BTreeSet<u64>,
    format: FormatConclusion,
    rule: RuleConclusion,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FormatConclusion {
    Matches,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuleConclusion {
    NotNeeded,
    Covered,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WindowCoverage {
    required: BTreeSet<u64>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    applied: BTreeSet<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    confirmations: Vec<Confirmation>,
}

impl WindowCoverage {
    pub fn new(required: BTreeSet<u64>) -> Self {
        Self {
            required,
            applied: BTreeSet::new(),
            confirmations: Vec::new(),
        }
    }

    pub fn mark_applied(&mut self, sequences: impl IntoIterator<Item = u64>) {
        self.applied.extend(
            sequences
                .into_iter()
                .filter(|seq| self.required.contains(seq)),
        );
    }

    pub fn is_applied(&self, seq: u64) -> bool {
        self.applied.contains(&seq)
    }

    fn acknowledged(&self, seq: u64) -> bool {
        self.is_applied(seq)
            || self
                .confirmations
                .iter()
                .any(|row| row.sequences.contains(&seq))
    }

    fn remaining(&self) -> BTreeSet<u64> {
        let mut pending = self.required.clone();
        for seq in self
            .applied
            .iter()
            .chain(self.confirmations.iter().flat_map(|row| &row.sequences))
        {
            pending.remove(seq);
        }
        pending
    }
}

impl Workflow {
    pub(super) fn confirm(&mut self, receipt: Confirmation) -> Result<()> {
        let coverage = self
            .window
            .as_mut()
            .and_then(|window| window.coverage.as_mut())
            .context("there is no active confirmation window; inspect status")?;
        if coverage.confirmations.contains(&receipt) {
            return Ok(());
        }
        ensure!(
            receipt.sequences.is_subset(&coverage.required),
            "confirmation includes a sequence outside the active window"
        );
        self.groups.validate_delivery_sequences(
            &receipt.group,
            receipt.assignment_id,
            &receipt.sequences,
        )?;
        self.groups
            .consume_lookahead(&receipt.group, &receipt.sequences);
        coverage.confirmations.push(receipt);
        Ok(())
    }

    pub(super) fn require_confirmed_review(&self, sequences: &BTreeSet<u64>) -> Result<()> {
        if let Some(coverage) = self
            .window
            .as_ref()
            .and_then(|window| window.coverage.as_ref())
        {
            ensure!(
                sequences
                    .intersection(&coverage.required)
                    .all(|&seq| coverage.acknowledged(seq)),
                "submit a confirmed receipt for active window sequences"
            );
        }
        Ok(())
    }

    pub(super) fn pending_confirmation(&self) -> Option<BTreeSet<u64>> {
        let coverage = self.window.as_ref()?.coverage.as_ref()?;
        let mut pending = coverage.remaining();
        for seq in self
            .groups
            .ready_fixes()
            .flat_map(|fix| &fix.sequences)
            .chain(self.rule_plans.pending().flat_map(|plan| plan.sequences()))
        {
            pending.remove(seq);
        }
        Some(pending)
    }

    pub fn window_ready(&self) -> bool {
        self.pending_confirmation()
            .is_some_and(|pending| pending.is_empty())
    }

    pub fn window_changes_ready(&self) -> bool {
        let Some(coverage) = self
            .window
            .as_ref()
            .and_then(|window| window.coverage.as_ref())
        else {
            return false;
        };
        self.groups
            .ready_fixes()
            .any(|fix| !fix.sequences.is_disjoint(&coverage.required))
            || self
                .rule_plans
                .pending()
                .any(|plan| !plan.sequences().is_disjoint(&coverage.required))
    }

    pub(super) fn failure_was_applied(&self, seq: u64) -> bool {
        self.window
            .as_ref()
            .and_then(|window| window.coverage.as_ref())
            .is_some_and(|coverage| coverage.is_applied(seq))
    }

    pub(super) fn require_window_candidate(&self, candidate: &Candidate) -> Result<()> {
        let coverage = self
            .window
            .as_ref()
            .and_then(|window| window.coverage.as_ref())
            .context("inspect status to load the confirmation window")?;
        ensure!(
            self.window_ready(),
            "complete all window confirmations before publishing a candidate"
        );
        for fix in self
            .groups
            .ready_fixes()
            .filter(|fix| !fix.sequences.is_disjoint(&coverage.required))
        {
            ensure!(
                candidate.included_fixes.contains(&fix.commit),
                "candidate must include window fix {}",
                fix.commit
            );
        }
        for plan in self
            .rule_plans
            .pending()
            .filter(|plan| !plan.sequences().is_disjoint(&coverage.required))
        {
            ensure!(
                candidate.included_rule_plans.contains(plan.id()),
                "candidate must include window rule plan {}",
                plan.id()
            );
        }
        Ok(())
    }

    pub(super) fn read_window_progress(&self) -> Option<Value> {
        let window = self.window.as_ref()?;
        let coverage = window.coverage.as_ref()?;
        let pending = self.pending_confirmation()?;
        let mut detail = window.handoff();
        detail["required_confirmations"] = json!(coverage.required.len());
        detail["pending_confirmations"] = json!(pending.len());
        if let Some(first) = pending.first() {
            detail["first_pending_seq"] = json!(first);
        }
        Some(detail)
    }

    pub(super) fn coverage_blocker(&self) -> Option<Value> {
        let pending = self.pending_confirmation()?;
        let window = self.window.as_ref()?;
        let seq = *pending.first()?;
        if window.is_unresolved(seq) {
            return Some(json!({
                "kind":"setup_required",
                "summary":"Resolve the first unowned window sequence.",
                "details":{"seq":seq, "reason":"unresolved_window_ownership"}
            }));
        }
        let gap = self.groups.gap_for_sequence(seq)?;
        Some(json!({
            "kind":"setup_required",
            "summary":"Resolve the reported gap for the first pending window sequence.",
            "details":{"seq":seq, "group":gap.group, "evidence":gap.evidence}
        }))
    }
}
