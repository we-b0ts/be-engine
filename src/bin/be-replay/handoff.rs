//! Reviewed work, delivery receipts, and candidate admission for a Replay round.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use traffic_e2e::{
    E2eEventSessionResult,
    event_work::{
        ApiConfirmation, DispatchPlan, Finding, Findings, normalize, validate_max_implementers,
        validate_scope,
    },
};
use uuid::Uuid;

mod api_review;
mod assignments;
#[cfg(test)]
mod tests;

const DEFAULT_IMPLEMENTERS: usize = 16;

#[derive(Clone, Copy)]
pub(super) enum AssignmentDetail {
    Summary,
    Full,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Workflow {
    repair: Option<Repair>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    earlier: BTreeMap<Uuid, Repair>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_review: Option<api_review::ApiReview>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Repair {
    attempt_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failed_sequence: Option<u64>,
    #[serde(default, alias = "blocker", skip_serializing_if = "Option::is_none")]
    first_unmatched: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_work: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    worktrees: BTreeMap<String, usize>,
    #[serde(default = "default_implementers")]
    max_implementers: usize,
    #[serde(deserialize_with = "read_saved_plan")]
    plan: DispatchPlan,
    fixes: Option<Vec<Fix>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    engine_gaps: BTreeMap<String, EngineGap>,
    candidate: Option<Candidate>,
}

fn default_implementers() -> usize {
    DEFAULT_IMPLEMENTERS
}

fn read_saved_plan<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<DispatchPlan, D::Error> {
    let mut plan = Value::deserialize(deserializer)?;
    let legacy_coordinator = plan
        .as_object_mut()
        .and_then(|plan| plan.remove("coordinator"));
    if let Some(Value::Array(legacy_waiting)) = legacy_coordinator
        && let Some(waiting) = plan.get_mut("waiting").and_then(Value::as_array_mut)
    {
        waiting.extend(legacy_waiting);
    }
    for group in ["implementers", "waiting"] {
        if let Some(findings) = plan.get_mut(group).and_then(Value::as_array_mut) {
            findings.retain_mut(|finding| {
                finding.as_object_mut().is_none_or(|entry| {
                    entry.remove("kind");
                    entry.remove("evidence");
                    entry.remove("code_paths");
                    entry.remove("blocked_by");
                    entry.remove("basis").as_ref().and_then(Value::as_str) != Some("hypothesis")
                })
            });
        }
    }
    serde_json::from_value(plan).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EngineGap {
    evidence: String,
    reported_during: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retried_on: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fix {
    root_cause: String,
    commit: String,
    checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Candidate {
    commit: String,
    included_fixes: BTreeSet<String>,
    checks: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Receipt {
    Fixes {
        attempt_id: Uuid,
        fixes: Vec<Fix>,
    },
    EngineGap {
        attempt_id: Uuid,
        root_cause: String,
        evidence: String,
    },
    Candidate {
        attempt_id: Uuid,
        commit: String,
        included_fixes: BTreeSet<String>,
        checks: Vec<String>,
    },
}

impl Workflow {
    pub(super) fn confirm_apis(
        &mut self,
        target: &Path,
        recording: &Path,
        confirmations: Vec<ApiConfirmation>,
        submissions: &Findings,
    ) -> Result<()> {
        if let Some(review) = &self.api_review {
            return review.check_resubmission(confirmations);
        }
        let current = self
            .repair
            .iter()
            .filter(|repair| repair.candidate.is_none());
        let related: Vec<_> = submissions
            .first_unmatched
            .iter()
            .chain(&submissions.others)
            .chain(current.flat_map(Repair::findings))
            .filter(|finding| {
                !self
                    .repairs()
                    .any(|repair| repair.has_delivery(&finding.root_cause))
            })
            .collect();
        let used_causes = self
            .repairs()
            .flat_map(Repair::findings)
            .chain(
                submissions
                    .first_unmatched
                    .iter()
                    .chain(&submissions.others),
            )
            .map(|finding| finding.root_cause.as_str())
            .collect();
        let review =
            api_review::ApiReview::load(target, recording, confirmations, &related, &used_causes)?;
        self.api_review = Some(review);
        Ok(())
    }

    pub(super) fn apis_reviewed(&self) -> bool {
        self.api_review.is_some()
    }

    pub(super) fn has_pending_api_work(&self) -> bool {
        self.pending_api_findings().next().is_some()
    }

    pub(super) fn max_implementers(&self) -> usize {
        self.repair
            .as_ref()
            .map_or(DEFAULT_IMPLEMENTERS, |repair| repair.max_implementers)
    }

    fn pending_api_findings(&self) -> impl Iterator<Item = &Finding> {
        self.api_review
            .iter()
            .flat_map(|review| review.tasks.values())
            .filter_map(|task| {
                let included = self
                    .repair
                    .iter()
                    .chain(self.earlier.values())
                    .any(|owner| owner.fix_was_integrated(self, &task.finding.root_cause));
                (!included).then_some(&task.finding)
            })
    }

    pub(super) fn queue_api_repairs(
        &mut self,
        attempt: &E2eEventSessionResult,
        max_implementers: usize,
    ) -> Result<()> {
        let attempt_id = attempt.attempt_id.parse()?;
        let mut findings: Vec<_> = self.pending_api_findings().cloned().collect();
        findings.sort_by_key(|finding| finding.sequences.first().copied());
        let Some(first) = findings.first() else {
            return Ok(());
        };
        validate_max_implementers(max_implementers)?;
        let mut repair = self.current(attempt).cloned().unwrap_or_else(|| Repair {
            attempt_id,
            base_commit: attempt.target_commit.clone(),
            failed_sequence: None,
            first_unmatched: None,
            api_work: None,
            worktrees: BTreeMap::new(),
            max_implementers,
            plan: DispatchPlan::default(),
            fixes: None,
            engine_gaps: BTreeMap::new(),
            candidate: None,
        });
        repair.api_work = Some(first.root_cause.clone());
        repair.max_implementers = max_implementers;
        self.retire_replayed_gap(attempt_id);
        repair.plan = self.schedule(&repair, findings);
        if let Some(previous) = self.repair.replace(repair)
            && previous.attempt_id != attempt_id
        {
            self.earlier.insert(previous.attempt_id, previous);
        }
        Ok(())
    }

    pub(super) fn current_plan(&self, attempt: &E2eEventSessionResult) -> Option<&DispatchPlan> {
        self.current(attempt).map(|repair| &repair.plan)
    }

    pub(super) fn set_plan(
        &mut self,
        attempt: &E2eEventSessionResult,
        failed_sequence: u64,
        submissions: Findings,
        max_implementers: usize,
    ) -> Result<&DispatchPlan> {
        let attempt_id = attempt.attempt_id.parse()?;
        let base_commit = attempt
            .target_commit
            .as_deref()
            .context("attempt lacks Target identity")?;
        validate_max_implementers(max_implementers)?;
        ensure!(
            failed_sequence > 0,
            "the failed attempt has no Source sequence to plan"
        );
        let current = self
            .repair
            .as_ref()
            .filter(|repair| repair.attempt_id == attempt_id);
        let existing_first = current.and_then(|repair| repair.first_unmatched.as_deref());
        let Findings {
            first_unmatched,
            others,
            apis: _,
        } = submissions;
        for finding in first_unmatched.iter().chain(&others) {
            validate_scope(finding)?;
            if let Some(previous) = current.and_then(|repair| repair.finding(&finding.root_cause)) {
                ensure!(
                    previous
                        .group
                        .as_ref()
                        .is_none_or(|group| Some(group) == finding.group.as_ref()),
                    "finding {} already belongs to group {}",
                    finding.root_cause,
                    previous.dispatch_group()
                );
            }
        }
        if let Some(finding) = &first_unmatched {
            ensure!(
                finding.sequences.contains(&failed_sequence),
                "first_unmatched must cover the first failed sequence {failed_sequence}"
            );
            ensure!(
                existing_first.is_none_or(|cause| cause == finding.root_cause),
                "the current attempt already has a different first_unmatched group"
            );
        }
        let first_cause = first_unmatched
            .as_ref()
            .map(|finding| finding.root_cause.as_str())
            .or(existing_first)
            .with_context(|| {
                format!("submit first_unmatched for the first failed sequence {failed_sequence}")
            })?
            .to_owned();
        ensure!(
            others
                .iter()
                .all(|finding| finding.root_cause != first_cause),
            "submit changes to the first unmatched group under first_unmatched"
        );
        let combined = normalize(
            self.pending_api_findings()
                .chain(current.into_iter().flat_map(Repair::findings))
                .cloned()
                .chain(first_unmatched)
                .chain(others)
                .collect(),
        )?;
        if let Some(repair) = current {
            ensure!(
                repair
                    .failed_sequence
                    .is_none_or(|sequence| sequence == failed_sequence)
                    && repair
                        .base_commit
                        .as_deref()
                        .is_none_or(|commit| commit == base_commit),
                "the reviewed plan belongs to another failure or Target revision"
            );
            if repair.candidate.is_some() {
                ensure!(
                    combined == normalize(repair.findings().cloned().collect())?,
                    "this attempt already has an integrated candidate"
                );
                return Ok(&self.repair.as_ref().expect("current repair").plan);
            }
        }
        let mut repair = current.cloned().unwrap_or_else(|| Repair {
            attempt_id,
            base_commit: None,
            failed_sequence: None,
            first_unmatched: None,
            api_work: None,
            worktrees: BTreeMap::new(),
            max_implementers,
            plan: DispatchPlan::default(),
            fixes: None,
            engine_gaps: BTreeMap::new(),
            candidate: None,
        });
        repair.base_commit = Some(base_commit.to_owned());
        repair.failed_sequence = Some(failed_sequence);
        repair.first_unmatched = Some(first_cause);
        repair.max_implementers = max_implementers;
        self.retire_replayed_gap(attempt_id);
        repair.plan = self.schedule(&repair, combined);
        if let Some(previous) = self.repair.replace(repair)
            && previous.attempt_id != attempt_id
        {
            self.earlier.insert(previous.attempt_id, previous);
        }
        Ok(&self.repair.as_ref().expect("plan just assigned").plan)
    }

    pub(super) fn report(
        &mut self,
        root: &Path,
        head: &str,
        attempt: &E2eEventSessionResult,
        receipt: Receipt,
    ) -> Result<()> {
        match receipt {
            Receipt::Fixes { attempt_id, fixes } => {
                self.accept_fixes(root, attempt_id, fixes)?;
                self.refresh_assignments(attempt);
            }
            Receipt::EngineGap {
                attempt_id,
                root_cause,
                evidence,
            } => {
                self.accept_engine_gap(
                    attempt_id,
                    &root_cause,
                    evidence,
                    attempt.attempt_id.parse()?,
                )?;
                self.refresh_assignments(attempt);
            }
            Receipt::Candidate {
                attempt_id,
                commit,
                included_fixes,
                checks,
            } => {
                let candidate = Candidate {
                    commit,
                    included_fixes,
                    checks,
                };
                let repair = self
                    .current(attempt)
                    .context("submit a reviewed plan for the current failed attempt first")?;
                let failed_commit = attempt
                    .target_commit
                    .as_deref()
                    .context("attempt lacks Target identity")?;
                ensure!(
                    attempt_id == repair.attempt_id,
                    "candidate refers to a stale attempt"
                );
                ensure!(
                    candidate.commit == head,
                    "candidate commit must be the current branch HEAD"
                );
                if repair.candidate.as_ref() == Some(&candidate) {
                    return Ok(());
                }
                let first = repair
                    .priority()
                    .context("no scheduled repair to integrate")?;
                let accepted = self.accepted_fix(first)
                    .context("record the accepted fix for the first unmatched group before publishing a candidate")?;
                ensure!(
                    candidate.included_fixes == BTreeSet::from([accepted.commit.to_owned()]),
                    "candidate must include exactly the accepted first unmatched fix"
                );
                validate_checks(&candidate.checks)?;
                if let Some(review) = &self.api_review {
                    review.validate_candidate(
                        root,
                        self.repairs()
                            .flat_map(|repair| repair.fixes.iter().flatten())
                            .filter_map(|fix| {
                                candidate
                                    .included_fixes
                                    .contains(&fix.commit)
                                    .then_some(fix.root_cause.as_str())
                            }),
                    )?;
                }
                ensure!(
                    head != failed_commit,
                    "candidate must advance the failed revision after integration"
                );
                ensure!(
                    is_ancestor(root, failed_commit, head)?,
                    "candidate must descend from the failed revision {failed_commit}"
                );
                self.repair.as_mut().expect("current plan").candidate = Some(candidate);
            }
        }
        Ok(())
    }

    pub(super) fn next(&self, attempt: &E2eEventSessionResult, head: &str) -> Option<Value> {
        self.next_with_assignment_detail(attempt, head, AssignmentDetail::Full)
    }

    pub(super) fn next_with_assignment_detail(
        &self,
        attempt: &E2eEventSessionResult,
        head: &str,
        detail: AssignmentDetail,
    ) -> Option<Value> {
        let repair = self.current(attempt)?;
        let attempt_id = repair.attempt_id.simple().to_string();
        let base_commit = &attempt.target_commit;
        if let Some(candidate) = &repair.candidate {
            return Some(if candidate.commit == head {
                let action = json!({
                    "kind":"advance_required", "summary":"Verify the registered Target candidate.",
                    "details":{"candidate_commit":candidate.commit},
                    "command":["run"]
                });
                self.with_parallel_assignments(action, detail)
            } else {
                json!({
                    "kind":"setup_required", "summary":"Restore the registered Target candidate, then retry.",
                    "details":{"candidate_commit":candidate.commit, "head":head},
                    "command":["run"]
                })
            });
        }
        let first = repair
            .priority()
            .filter(|cause| repair.finding(cause).is_some())?;
        if let Some(gap) = self.engine_gap(repair, first) {
            return Some(json!({
                "kind":"setup_required", "summary":"Resolve the reported engine gap, then retry Replay.",
                "details":gap, "command":["run"]
            }));
        }
        if let Some(fix) = self.accepted_fix(first) {
            let action = json!({
                "kind":"integration_required", "summary":"Integrate the accepted fix for the current priority.",
                "details":{"role":"code-integrator", "attempt_id":attempt_id, "base_commit":base_commit, "fixes":[fix]},
                "command":["report", "--file", "<candidate.json>"]
            });
            return Some(self.with_parallel_assignments(action, detail));
        }
        let assignments = self.current_assignments(first);
        if assignments.is_empty() {
            return None;
        }
        let assignments = assignments::assignment_rows(&assignments, detail);
        Some(json!({
            "kind":"implementation_required", "summary":"Assign or follow the eligible Replay fixes.",
            "details":{"role":"api-implementer", "first_unmatched":repair.first_unmatched, "priority":first, "assignments":assignments},
            "command":["report", "--file", "<delivery.json>"]
        }))
    }

    pub(super) fn with_parallel_assignments(
        &self,
        mut action: Value,
        detail: AssignmentDetail,
    ) -> Value {
        let assignments = self.current_assignments("");
        if !assignments.is_empty() {
            action["details"]["assignments"] = assignments::assignment_rows(&assignments, detail);
        }
        action
    }

    pub(super) fn require_replay_candidate(
        &self,
        attempt: &E2eEventSessionResult,
        head: &str,
    ) -> Result<()> {
        let Some(repair) = self.current(attempt) else {
            return Ok(());
        };
        if let Some(candidate) = &repair.candidate {
            ensure!(
                candidate.commit == head,
                "restore the registered candidate {} before running Replay",
                candidate.commit
            );
        } else if let Some(first) = repair.priority() {
            ensure!(
                self.engine_gap(repair, first).is_some(),
                "register the integrated candidate before running Replay; inspect be-replay status"
            );
        }
        Ok(())
    }

    pub(super) fn has_candidate(&self, attempt: &E2eEventSessionResult) -> bool {
        self.current(attempt)
            .is_some_and(|repair| repair.candidate.is_some())
    }

    fn current(&self, attempt: &E2eEventSessionResult) -> Option<&Repair> {
        let attempt_id = attempt.attempt_id.parse::<Uuid>().ok()?;
        self.repair
            .as_ref()
            .filter(|repair| repair.attempt_id == attempt_id)
    }

    fn refresh_assignments(&mut self, attempt: &E2eEventSessionResult) {
        if let Some(repair) = self
            .current(attempt)
            .filter(|repair| repair.candidate.is_none())
        {
            let Some(first) = repair.priority() else {
                return;
            };
            if self.accepted_fix(first).is_some() || self.engine_gap(repair, first).is_some() {
                return;
            }
            let plan = self.schedule(repair, repair.findings().cloned().collect());
            self.repair.as_mut().expect("current plan").plan = plan;
        }
    }
}

fn validate_checks(checks: &[String]) -> Result<()> {
    ensure!(
        !checks.is_empty() && checks.iter().all(|check| !check.trim().is_empty()),
        "delivery must include its check results"
    );
    Ok(())
}

fn validate_commit(root: &Path, commit: &str) -> Result<()> {
    ensure!(
        super::round::is_full_commit_id(commit),
        "delivery requires a full Git commit ID"
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "-t", commit])
        .output()
        .context("read delivered Git object")?;
    ensure!(
        output.status.success() && output.stdout == b"commit\n",
        "unknown delivery commit {commit}"
    );
    Ok(())
}

fn is_ancestor(root: &Path, base: &str, commit: &str) -> Result<bool> {
    Ok(Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["merge-base", "--is-ancestor", base, commit])
        .status()
        .context("compare delivery and base commits")?
        .success())
}
