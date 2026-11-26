//! Persist Replay handoffs by recording, and admit candidates that address the current failure.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use traffic_e2e::{
    E2eEventSessionResult, config::api_catalog, event_work::ApiConfirmation, session,
};
use uuid::Uuid;

mod api_review;
mod groups;
#[cfg(test)]
mod tests;

use api_review::ApiReview;
use groups::{Fix, Gap, Groups, WorkItem};

const DEFAULT_IMPLEMENTERS: usize = 16;

#[derive(Clone, Copy)]
pub(super) enum AssignmentDetail {
    Summary,
    Full,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct Workflow {
    api_review: Option<ApiReview>,
    api_work_queued: bool,
    groups: Groups,
    max_implementers: usize,
    window: Option<Window>,
    failure: Option<Failure>,
    owners: BTreeMap<String, Ownership>,
    candidate: Option<Candidate>,
}

impl Default for Workflow {
    fn default() -> Self {
        Self {
            api_review: None,
            api_work_queued: false,
            groups: Groups::default(),
            max_implementers: DEFAULT_IMPLEMENTERS,
            window: None,
            failure: None,
            owners: BTreeMap::new(),
            candidate: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Window {
    from_seq: u64,
    through_seq: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Failure {
    attempt_id: Uuid,
    seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ownership {
    pub seq: u64,
    pub scope: String,
    pub group: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub apis: Option<Vec<ApiConfirmation>>,
    pub ownership: Option<Ownership>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Candidate {
    attempt_id: Uuid,
    commit: String,
    included_fixes: BTreeSet<String>,
    checks: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Receipt {
    Fixes {
        fixes: Vec<Fix>,
    },
    Review {
        group: String,
        assignment_id: Uuid,
        sequences: BTreeSet<u64>,
        checks: Vec<String>,
    },
    EngineGap {
        group: String,
        assignment_id: Uuid,
        sequences: BTreeSet<u64>,
        evidence: String,
    },
    Candidate {
        attempt_id: Uuid,
        commit: String,
        included_fixes: BTreeSet<String>,
        checks: Vec<String>,
    },
}

impl Receipt {
    pub fn is_candidate(&self) -> bool {
        matches!(self, Self::Candidate { .. })
    }
}

impl Workflow {
    pub fn needs_api_review(&self, target: &Path, recording: &Path) -> Result<bool> {
        Ok(self.api_review.is_none() && !session::recorded_apis(target, recording)?.is_empty())
    }

    pub fn confirm_apis(
        &mut self,
        target: &Path,
        recording: &Path,
        rows: Vec<ApiConfirmation>,
    ) -> Result<()> {
        if let Some(review) = &self.api_review {
            return review.check_resubmission(rows);
        }
        self.api_review = Some(ApiReview::load(target, recording, rows)?);
        Ok(())
    }

    pub fn set_max_implementers(&mut self, max: usize) -> Result<()> {
        traffic_e2e::event_work::validate_max_implementers(max)?;
        self.max_implementers = max;
        Ok(())
    }

    pub fn needs_api_work_queue(&self) -> bool {
        self.api_review.is_some() && !self.api_work_queued
    }

    pub fn queue_api_work(&mut self, base: &str) {
        let Some(review) = self.api_review.as_ref().filter(|_| !self.api_work_queued) else {
            return;
        };
        for task in review.tasks.values() {
            self.groups.enqueue(
                &task.assignment.group,
                WorkItem {
                    scope: task.assignment.scope.clone(),
                    sequences: task.assignment.sequences.clone(),
                    apis: task.apis.clone(),
                },
                base,
            );
        }
        self.api_work_queued = true;
    }

    pub fn failure_observed(&self, attempt: &E2eEventSessionResult, seq: u64) -> bool {
        self.failure.as_ref().is_some_and(|failure| {
            failure.seq == seq && attempt_uuid(attempt).ok() == Some(failure.attempt_id)
        })
    }

    pub fn observe_failure(
        &mut self,
        target: &Path,
        recording: &Path,
        base: &str,
        attempt: &E2eEventSessionResult,
        seq: u64,
    ) -> Result<()> {
        if self.failure_observed(attempt, seq) {
            return Ok(());
        }
        let replayed_same_sequence = self
            .failure
            .as_ref()
            .is_some_and(|failure| failure.seq == seq);
        let window_owner = if self
            .window
            .as_ref()
            .is_some_and(|window| window.from_seq == seq)
        {
            None
        } else {
            let after = self
                .window
                .as_ref()
                .filter(|window| (window.from_seq..=window.through_seq).contains(&seq))
                .map_or(0, |window| window.through_seq);
            let window = session::dispatch_window(target, recording, seq, after)?;
            for api in window.apis {
                if let Some((scope, group)) = self.api_scope(&api.api, api.group.as_deref()) {
                    self.groups.enqueue(
                        &group,
                        WorkItem {
                            scope,
                            sequences: api.sequences,
                            apis: Vec::new(),
                        },
                        base,
                    );
                }
            }
            self.window = Some(Window {
                from_seq: window.from_seq,
                through_seq: window.through_seq,
            });
            window.failure_owner
        };
        self.failure = Some(Failure {
            attempt_id: attempt_uuid(attempt)?,
            seq,
        });
        if let Some(owner) = self.owners.get(&seq.to_string()).cloned() {
            if replayed_same_sequence {
                self.groups.dismiss_gap(&owner.group, seq);
            }
            self.enqueue_owner(&owner, base);
        } else if let Some(owner) = window_owner {
            let resolved = if let Some(label) = owner.scope.strip_prefix("api:") {
                self.api_scope(label, owner.group.as_deref())
            } else {
                owner.group.map(|group| (owner.scope, group))
            };
            if let Some((scope, group)) = resolved {
                self.set_owner(Ownership { seq, scope, group }, base)?;
            }
        }
        Ok(())
    }

    pub fn set_owner(&mut self, mut owner: Ownership, base: &str) -> Result<()> {
        ensure!(
            self.failure
                .as_ref()
                .is_some_and(|failure| failure.seq == owner.seq),
            "ownership must describe the current failed sequence"
        );
        if let Some(label) = owner.scope.strip_prefix("api:")
            && let Some((scope, group)) = self.api_scope(label, None)
        {
            ensure!(owner.group == group, "use the confirmed API group {group}");
            owner.scope = scope;
        }
        api_catalog::validate_group(&owner.group)?;
        validate_scope(&owner.scope)?;
        let key = owner.seq.to_string();
        if let Some(prior) = self.owners.get(&key) {
            ensure!(prior == &owner, "this Source sequence already has an owner");
        } else {
            self.owners.insert(key, owner.clone());
        }
        self.enqueue_owner(&owner, base);
        Ok(())
    }

    fn api_scope(&self, label: &str, known_group: Option<&str>) -> Option<(String, String)> {
        self.api_review
            .as_ref()
            .and_then(|review| review.api_scope(label))
            .or_else(|| known_group.map(|group| (format!("api:{label}"), group.to_owned())))
    }

    fn enqueue_owner(&mut self, owner: &Ownership, base: &str) {
        if self.groups.gap(&owner.group, owner.seq).is_none()
            && !self.groups.pending(&owner.group, owner.seq)
            && !self
                .groups
                .ready_fixes()
                .any(|fix| fix.group == owner.group && fix.sequences.contains(&owner.seq))
        {
            self.groups.reopen(
                &owner.group,
                WorkItem {
                    scope: owner.scope.clone(),
                    sequences: [owner.seq].into(),
                    apis: Vec::new(),
                },
                base,
            );
        }
    }

    pub fn active_worktree_slots(&self) -> impl Iterator<Item = usize> + '_ {
        self.groups.active_slots()
    }

    pub fn reserve_worktrees(&mut self, allocate: impl FnMut() -> Result<usize>) -> Result<()> {
        self.groups.reserve(self.max_implementers, allocate)
    }

    pub fn with_assignments(&self, mut action: Value, detail: AssignmentDetail) -> Value {
        let assignments = self.groups.assignments(detail);
        if assignments.as_array().is_some_and(|rows| !rows.is_empty()) {
            action["details"]["assignments"] = assignments;
        }
        action
    }

    pub fn implementation_action(&self) -> Value {
        let (kind, summary) = if self.groups.has_active_assignments() {
            (
                "implementation_required",
                "Dispatch or follow the assigned groups.",
            )
        } else {
            (
                "wait_required",
                "Wait for an available implementer or an updated handoff.",
            )
        };
        json!({
            "kind":kind, "summary":summary,
            "details":{"role":"api-implementer"}, "command":["report","--file","<delivery.json>"]
        })
    }

    pub fn failed_action(&self, seq: u64) -> Value {
        let Some(owner) = self.owners.get(&seq.to_string()) else {
            return json!({
                "kind":"ownership_required", "summary":"Identify the owner of the current failed event.",
                "details":{"role":"issue-analyst", "seq":seq},
                "command":["plan","--findings","<ownership.json>"]
            });
        };
        if let Some(mut action) = self.integration_action(Some(owner)) {
            action["details"]["group"] = json!(owner.group);
            return action;
        }
        if let Some(gap) = self.groups.gap(&owner.group, seq) {
            return json!({
                "kind":"setup_required",
                "summary":"Resolve the reported engine gap, then retry Replay.",
                "details":{"group":owner.group, "scope":owner.scope, "evidence":gap.evidence},
                "command":["run"]
            });
        }
        let mut action = self.implementation_action();
        action["details"]["group"] = json!(owner.group);
        action["details"]["scope"] = json!(owner.scope);
        action
    }

    pub fn pending_api_work(&self) -> bool {
        self.groups.has_pending_api_work()
    }

    pub fn has_lookahead_work(&self) -> bool {
        self.groups.has_lookahead_work()
    }

    pub fn retire_lookahead_work(&mut self) {
        self.groups.retire_lookahead_work();
    }

    pub fn integration_action(&self, owner: Option<&Ownership>) -> Option<Value> {
        let fixes: Vec<_> = self.groups.ready_fixes().collect();
        if fixes.is_empty() || !fixes.iter().any(|fix| covers(owner, fix)) {
            return None;
        }
        Some(json!({
            "kind":"integration_required",
            "summary":"Integrate the accepted delivery and any compatible ready fixes.",
            "details":{"role":"code-integrator", "fixes":fixes},
            "command":["report","--file","<candidate.json>"]
        }))
    }

    pub fn candidate_commit(&self, attempt: &E2eEventSessionResult) -> Option<&str> {
        let id = attempt_uuid(attempt).ok()?;
        self.candidate
            .as_ref()
            .filter(|candidate| candidate.attempt_id == id)
            .map(|candidate| candidate.commit.as_str())
    }

    pub fn has_candidate(&self, attempt: &E2eEventSessionResult) -> bool {
        self.candidate_commit(attempt).is_some()
    }

    pub fn report(
        &mut self,
        root: &Path,
        head: &str,
        attempt: Option<&E2eEventSessionResult>,
        seq: Option<u64>,
        receipt: Receipt,
    ) -> Result<()> {
        match receipt {
            Receipt::Fixes { fixes } => self.groups.accept_fixes(root, fixes),
            Receipt::Review {
                group,
                assignment_id,
                sequences,
                checks,
            } => {
                ensure!(
                    seq.is_none_or(|seq| !sequences.contains(&seq)),
                    "the current failed sequence requires a repair or an engine gap"
                );
                self.groups.review(&group, assignment_id, sequences, checks)
            }
            Receipt::EngineGap {
                group,
                assignment_id,
                sequences,
                evidence,
            } => self.groups.accept_gap(Gap {
                group,
                assignment_id,
                sequences,
                evidence,
            }),
            Receipt::Candidate {
                attempt_id,
                commit,
                included_fixes,
                checks,
            } => {
                let attempt =
                    attempt.context("publish a candidate for a finished Replay attempt")?;
                self.accept_candidate(
                    root,
                    head,
                    attempt,
                    seq,
                    Candidate {
                        attempt_id,
                        commit,
                        included_fixes,
                        checks,
                    },
                )
            }
        }
    }

    fn accept_candidate(
        &mut self,
        root: &Path,
        head: &str,
        attempt: &E2eEventSessionResult,
        seq: Option<u64>,
        candidate: Candidate,
    ) -> Result<()> {
        ensure!(
            candidate.attempt_id == attempt_uuid(attempt)?,
            "candidate refers to a stale attempt"
        );
        ensure!(
            candidate.commit == head,
            "candidate commit must be the current branch HEAD"
        );
        if self.candidate.as_ref() == Some(&candidate) {
            return Ok(());
        }
        ensure!(
            !self.has_candidate(attempt),
            "a candidate is already registered for this attempt"
        );
        validate_checks(&candidate.checks)?;
        let previous = attempt
            .target_commit
            .as_deref()
            .context("attempt lacks Target identity")?;
        ensure!(
            previous != head && is_ancestor(root, previous, head)?,
            "candidate must advance the Target revision {previous}"
        );
        let owner = seq
            .map(|seq| {
                self.owners
                    .get(&seq.to_string())
                    .context("confirm the current failed event's owner")
            })
            .transpose()?;
        let ready: Vec<_> = self
            .groups
            .ready_fixes()
            .filter(|fix| candidate.included_fixes.contains(&fix.commit))
            .collect();
        ensure!(
            ready
                .iter()
                .map(|fix| &fix.commit)
                .collect::<BTreeSet<_>>()
                .len()
                == candidate.included_fixes.len(),
            "candidate includes an unaccepted or already integrated delivery"
        );
        ensure!(
            ready.iter().any(|fix| covers(owner, fix)),
            "candidate must include an accepted delivery covering the current failure"
        );
        ApiReview::validate_catalog(root, self.groups.api_work_for(&candidate.included_fixes))?;
        self.groups.mark_integrated(&candidate.included_fixes);
        self.candidate = Some(candidate);
        Ok(())
    }
}

fn attempt_uuid(attempt: &E2eEventSessionResult) -> Result<Uuid> {
    Ok(attempt.attempt_id.parse()?)
}

fn covers(owner: Option<&Ownership>, fix: &Fix) -> bool {
    owner.is_none_or(|owner| owner.group == fix.group && fix.sequences.contains(&owner.seq))
}

fn validate_scope(scope: &str) -> Result<()> {
    let is_api = scope
        .strip_prefix("api:")
        .and_then(|api| api.split_once(' '))
        .is_some_and(|(method, path)| {
            !method.is_empty()
                && method
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
                && path.starts_with('/')
                && !path.contains(char::is_whitespace)
        });
    let is_job = scope
        .strip_prefix("job:")
        .is_some_and(|name| !name.is_empty() && !name.contains(char::is_whitespace));
    ensure!(
        is_api || is_job || matches!(scope, "startup" | "shutdown"),
        "scope must be api:METHOD /path, job:NAME, startup, or shutdown"
    );
    Ok(())
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
