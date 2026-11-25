//! Reviewed work and delivery receipts for the latest failed attempt.
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use traffic_e2e::{E2eEventSessionResult, event_work::DispatchPlan};
use uuid::Uuid;

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Workflow {
    repair: Option<Repair>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Repair {
    attempt_id: Uuid,
    plan: DispatchPlan,
    fixes: Option<Vec<Fix>>,
    candidate: Option<Candidate>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fix {
    root_cause: String,
    commit: String,
    checks: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    Candidate {
        attempt_id: Uuid,
        commit: String,
        included_fixes: BTreeSet<String>,
        checks: Vec<String>,
    },
}

impl Workflow {
    pub(super) fn set_plan(
        &mut self,
        attempt: &E2eEventSessionResult,
        plan: DispatchPlan,
    ) -> Result<&DispatchPlan> {
        let attempt_id = attempt.attempt_id.parse()?;
        if let Some(repair) = self
            .repair
            .as_mut()
            .filter(|repair| repair.attempt_id == attempt_id)
        {
            ensure!(
                repair.plan == plan || (repair.fixes.is_none() && repair.candidate.is_none()),
                "this attempt already has deliveries for its reviewed plan"
            );
            repair.plan = plan;
        } else {
            self.repair = Some(Repair {
                attempt_id,
                plan,
                fixes: None,
                candidate: None,
            });
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
        let expected_id = attempt.attempt_id.parse::<Uuid>()?;
        let repair = self
            .repair
            .as_mut()
            .filter(|repair| repair.attempt_id == expected_id)
            .context("submit a reviewed plan for the current failed attempt first")?;
        let failed_commit = attempt
            .target_commit
            .as_deref()
            .context("attempt lacks Target identity")?;
        match receipt {
            Receipt::Fixes { attempt_id, fixes } => {
                ensure!(attempt_id == expected_id, "fixes refer to a stale attempt");
                if repair.fixes.as_ref() == Some(&fixes) {
                    return Ok(());
                }
                ensure!(
                    head == failed_commit,
                    "record accepted fixes before changing the canonical branch"
                );
                ensure!(
                    repair.fixes.is_none() && repair.candidate.is_none(),
                    "integration batch is already recorded"
                );
                ensure!(
                    !fixes.is_empty(),
                    "fixes receipt must include an accepted repair"
                );
                let mut causes = BTreeSet::new();
                for fix in &fixes {
                    ensure!(
                        repair
                            .plan
                            .implementers
                            .iter()
                            .any(|finding| finding.root_cause == fix.root_cause),
                        "{} was not assigned for implementation",
                        fix.root_cause
                    );
                    ensure!(
                        causes.insert(&fix.root_cause),
                        "duplicate accepted root cause {}",
                        fix.root_cause
                    );
                    validate_checks(&fix.checks)?;
                    validate_commit(root, &fix.commit)?;
                }
                repair.fixes = Some(fixes);
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
                ensure!(
                    attempt_id == expected_id,
                    "candidate refers to a stale attempt"
                );
                ensure!(
                    candidate.commit == head,
                    "candidate commit must be the current branch HEAD"
                );
                if repair.candidate.as_ref() == Some(&candidate) {
                    return Ok(());
                }
                ensure!(
                    repair.fixes.is_some() || repair.plan.implementers.is_empty(),
                    "record the accepted implementation fixes before publishing a candidate"
                );
                let accepted = repair
                    .fixes
                    .iter()
                    .flatten()
                    .map(|fix| fix.commit.clone())
                    .collect();
                ensure!(
                    candidate.included_fixes == accepted,
                    "candidate must cover exactly the accepted fix commits"
                );
                validate_checks(&candidate.checks)?;
                if repair.fixes.is_some() {
                    ensure!(
                        head != failed_commit,
                        "candidate must advance the failed revision after integration"
                    );
                }
                ensure!(
                    Command::new("git")
                        .arg("-C")
                        .arg(root)
                        .args(["merge-base", "--is-ancestor", failed_commit, head])
                        .status()
                        .context("compare candidate to the failed revision")?
                        .success(),
                    "candidate must descend from the failed revision {failed_commit}"
                );
                repair.candidate = Some(candidate);
            }
        }
        Ok(())
    }

    pub(super) fn next(&self, attempt: &E2eEventSessionResult, head: &str) -> Option<Value> {
        let repair = self.current(attempt)?;
        let attempt_id = repair.attempt_id;
        if let Some(candidate) = &repair.candidate {
            return Some(if candidate.commit == head {
                json!({"action":"verify_candidate", "attempt_id":attempt_id, "candidate":candidate, "run":["run"]})
            } else {
                json!({
                    "action":"restore_candidate", "attempt_id":attempt_id, "candidate":candidate,
                    "head":head, "report":["report", "--file", "<candidate.json>"]
                })
            });
        }
        if let Some(fixes) = &repair.fixes {
            return Some(json!({
                "action":"integrate_candidate", "attempt_id":attempt_id, "base_commit":attempt.target_commit,
                "fixes":fixes, "report":["report", "--file", "<candidate.json>"]
            }));
        }
        Some(json!({
            "action": if repair.plan.implementers.is_empty() { "review_findings" } else { "implement_fixes" },
            "attempt_id":attempt_id, "base_commit":attempt.target_commit, "plan":repair.plan,
            "report":["report", "--file", "<delivery.json>"]
        }))
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
        } else {
            ensure!(
                repair.fixes.is_none() && repair.plan.implementers.is_empty(),
                "register the integrated candidate before running Replay; inspect be-replay status"
            );
        }
        Ok(())
    }

    fn current(&self, attempt: &E2eEventSessionResult) -> Option<&Repair> {
        let attempt_id = attempt.attempt_id.parse::<Uuid>().ok()?;
        self.repair
            .as_ref()
            .filter(|repair| repair.attempt_id == attempt_id)
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
