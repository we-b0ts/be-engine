//! Persist Replay handoffs by recording, and admit candidates that address the current failure.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use traffic_e2e::{
    E2eEventSessionResult,
    config::api_catalog::{self, ApiCatalog},
    event_work::{ApiConfirmation, ApiGrouping},
    session::{self, RecordedApi},
};
use uuid::Uuid;

mod api_backlog;
mod api_grouping;
mod delegation;
mod groups;
#[cfg(test)]
mod tests;

pub(super) use api_backlog::ApiBacklog;
pub(super) use api_grouping::CatalogUpdate;
pub(super) use delegation::{DispatchState, Registration, Task};
use groups::{Fix, Gap, Groups, ImplementerUpdate, WorkItem};

const DEFAULT_IMPLEMENTERS: usize = 16;

#[derive(Clone, Copy)]
pub(super) enum AssignmentDetail {
    Summary,
    Full,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct Workflow {
    groups: Groups,
    max_implementers: usize,
    window: Option<Window>,
    failure: Option<Failure>,
    owners: BTreeMap<String, Ownership>,
    candidate: Option<Candidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_registration: Option<Registration>,
}

impl Default for Workflow {
    fn default() -> Self {
        Self {
            groups: Groups::default(),
            max_implementers: DEFAULT_IMPLEMENTERS,
            window: None,
            failure: None,
            owners: BTreeMap::new(),
            candidate: None,
            task_registration: None,
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

impl Ownership {
    pub fn resolve_api(&mut self, target: &Path) -> Result<()> {
        let Some((method, path)) = self
            .scope
            .strip_prefix("api:")
            .and_then(|api| api.split_once(' '))
        else {
            return Ok(());
        };
        let catalog = ApiCatalog::load(&target.join(api_catalog::PATH))?.unwrap_or_default();
        if let Some(pattern) = api_catalog::matching_case_pattern(&catalog.case_paths(), path) {
            let group = &catalog.routes()[pattern];
            ensure!(self.group == *group, "use the catalog API group {group}");
            self.scope = format!("api:{method} {pattern}");
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub task_id: String,
    pub agent_handle: String,
    pub apis: Option<Vec<ApiGrouping>>,
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
    TaskDispatch {
        task_id: String,
        agent_handle: String,
        state: DispatchState,
    },
    Implementers {
        workers: Vec<ImplementerUpdate>,
    },
    Fixes {
        fixes: Vec<Fix>,
    },
    Review {
        group: String,
        assignment_id: Uuid,
        sequences: BTreeSet<u64>,
        checks: Vec<String>,
        #[serde(default)]
        confirms_apis: bool,
    },
    EngineGap {
        group: String,
        assignment_id: Uuid,
        sequences: BTreeSet<u64>,
        evidence: String,
    },
    Candidate {
        task_id: String,
        agent_handle: String,
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
    pub fn task_action(&self, task: &Task) -> Value {
        task.action(self.task_registration.as_ref())
    }

    pub fn require_task_delivery(&self, task: &Task, binding: &Registration) -> Result<()> {
        task.require_delivery(self.task_registration.as_ref(), binding)
    }

    pub fn set_max_implementers(&mut self, max: usize) -> Result<()> {
        traffic_e2e::event_work::validate_max_implementers(max)?;
        self.max_implementers = max;
        Ok(())
    }

    pub fn restore_api_backlog(&self, backlog: &mut ApiBacklog) {
        for api in self.groups.open_apis() {
            backlog.restore_pending(api);
        }
    }

    pub fn refresh_api_work(
        &mut self,
        inventory: &[RecordedApi],
        backlog: &ApiBacklog,
        base: &str,
    ) {
        self.groups.refresh_api_work(inventory, backlog, base);
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
                if let Some(group) = api.group {
                    self.groups.enqueue(
                        &group,
                        WorkItem {
                            scope: format!("api:{}", api.api),
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
        } else if let Some(owner) = window_owner
            && let Some(group) = owner.group
        {
            self.set_owner(
                Ownership {
                    seq,
                    scope: owner.scope,
                    group,
                },
                base,
            )?;
        }
        Ok(())
    }

    pub fn set_owner(&mut self, owner: Ownership, base: &str) -> Result<()> {
        ensure!(
            self.failure
                .as_ref()
                .is_some_and(|failure| failure.seq == owner.seq),
            "ownership must describe the current failed sequence"
        );
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

    pub fn clear_runtime_handles(&mut self) {
        self.groups.clear_worker_handles();
        self.task_registration = None;
    }

    pub fn first_run_action(&self) -> Option<Value> {
        let queued = self.groups.queued_api_groups();
        (queued > 0).then(|| json!({
            "kind":"implementation_required",
            "summary":"Follow active implementers and report a finished delivery to free a slot for the remaining API groups.",
            "details":{"role":"api-implementer", "queued_api_groups":queued}
        }))
    }

    pub fn with_assignments(
        &self,
        mut action: Value,
        detail: AssignmentDetail,
        first_run: bool,
    ) -> Value {
        let pending_dispatch = self.groups.pending_dispatch();
        let pending_worker_status = self.groups.pending_worker_status();
        if action["details"]["reason"] == "engine_changed" && self.groups.needs_api_dispatch() {
            action = self
                .first_run_action()
                .unwrap_or_else(|| self.implementation_action());
        }
        let needs_workers = match action["kind"].as_str() {
            Some("advance_required") => first_run,
            Some("implementation_required" | "wait_required") => true,
            _ => false,
        };
        if needs_workers && pending_dispatch > 0 {
            action = json!({
                "kind":"dispatch_required",
                "summary":"Start the unregistered implementers in parallel. Register each handle after the runtime returns it.",
                "details":{"role":"api-implementer"}
            });
        } else if needs_workers && pending_worker_status > 0 {
            action = json!({
                "kind":"worker_status_required",
                "summary":"Check the registered implementers in the agent runtime. Report the observed states.",
                "details":{"role":"api-implementer"}
            });
        }
        if pending_dispatch > 0 {
            action["details"]["pending_dispatch"] = json!(pending_dispatch);
        }
        if pending_worker_status > 0 {
            action["details"]["pending_worker_status"] = json!(pending_worker_status);
        }
        let integration = action["details"]["task"]["requirement"] == "integration_required";
        if pending_dispatch > 0
            || pending_worker_status > 0
            || integration
            || action["kind"] == "implementation_required"
        {
            action["query"] = json!(["status", "--with-assignments"]);
        }
        if matches!(detail, AssignmentDetail::Full) {
            if self.groups.has_active_assignments() {
                action["details"]["assignments"] = self.groups.assignments();
            }
            if integration {
                action["details"]["fixes"] = json!(self.groups.ready_fixes().collect::<Vec<_>>());
            }
        }
        action
    }

    pub fn implementation_action(&self) -> Value {
        let (kind, summary) = if self.groups.has_active_assignments() {
            (
                "implementation_required",
                "Follow the registered implementers and report ready deliveries.",
            )
        } else {
            (
                "wait_required",
                "Wait for an available implementer or an updated handoff.",
            )
        };
        json!({
            "kind":kind, "summary":summary,
            "details":{"role":"api-implementer"}
        })
    }

    pub fn failure_owner(&self, seq: u64) -> Option<&Ownership> {
        self.owners.get(&seq.to_string())
    }

    pub fn repair_action(&self, owner: &Ownership) -> Value {
        if let Some(gap) = self.groups.gap(&owner.group, owner.seq) {
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

    pub fn ready_integration(&self, owner: Option<&Ownership>) -> Option<usize> {
        if !self.groups.ready_fixes().any(|fix| covers(owner, fix)) {
            return None;
        }
        Some(self.groups.ready_fixes().count())
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
        current_task: Option<&Task>,
        receipt: Receipt,
    ) -> Result<Vec<ApiConfirmation>> {
        match receipt {
            Receipt::TaskDispatch {
                task_id,
                agent_handle,
                state,
            } => {
                let task = current_task
                    .context("no delegated task is currently required; inspect status")?;
                task.register(
                    &mut self.task_registration,
                    Registration {
                        task_id,
                        agent_handle,
                    },
                    state,
                )?;
                Ok(Vec::new())
            }
            Receipt::Implementers { workers } => {
                self.groups.update_implementers(workers)?;
                Ok(Vec::new())
            }
            Receipt::Fixes { fixes } => {
                self.groups.accept_fixes(root, fixes)?;
                Ok(Vec::new())
            }
            Receipt::Review {
                group,
                assignment_id,
                sequences,
                checks,
                confirms_apis,
            } => {
                ensure!(
                    seq.is_none_or(|seq| !sequences.contains(&seq)),
                    "the current failed sequence requires a repair or an engine gap"
                );
                self.groups.review(
                    &group,
                    assignment_id,
                    sequences,
                    checks,
                    confirms_apis.then_some(root),
                )
            }
            Receipt::EngineGap {
                group,
                assignment_id,
                sequences,
                evidence,
            } => {
                self.groups.accept_gap(Gap {
                    group,
                    assignment_id,
                    sequences,
                    evidence,
                })?;
                Ok(Vec::new())
            }
            Receipt::Candidate {
                task_id,
                agent_handle,
                attempt_id,
                commit,
                included_fixes,
                checks,
            } => {
                let attempt =
                    attempt.context("publish a candidate for a finished Replay attempt")?;
                let task = Task::integration(
                    &attempt.run_key,
                    &attempt.attempt_id,
                    self.groups.ready_fixes().count(),
                    seq,
                );
                self.require_task_delivery(
                    &task,
                    &Registration {
                        task_id,
                        agent_handle,
                    },
                )?;
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
    ) -> Result<Vec<ApiConfirmation>> {
        ensure!(
            candidate.attempt_id == attempt_uuid(attempt)?,
            "candidate refers to a stale attempt"
        );
        ensure!(
            candidate.commit == head,
            "candidate commit must be the current branch HEAD"
        );
        if self.candidate.as_ref() == Some(&candidate) {
            return Ok(Vec::new());
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
        api_grouping::validate_committed_catalog(
            root,
            self.groups.api_work_for(&candidate.included_fixes),
        )?;
        let completed = self.groups.mark_integrated(&candidate.included_fixes);
        self.candidate = Some(candidate);
        Ok(completed)
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
