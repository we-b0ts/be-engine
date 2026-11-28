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
mod confirmation;
mod delegation;
mod groups;
mod lookahead;
pub(crate) mod rule_plans;
mod sequences;
#[cfg(test)]
mod tests;

pub(super) use api_backlog::ApiBacklog;
pub(super) use api_grouping::CatalogUpdate;
use confirmation::Confirmation;
pub(super) use delegation::{DispatchState, Registration, Task};
use groups::{Fix, Gap, Groups, ImplementerUpdate, WorkItem};
pub(super) use lookahead::WindowFinding;
use lookahead::{Claim, Window, api_scope_path};
use rule_plans::RulePlans;
pub(super) use sequences::read_receipt;
pub(crate) use sequences::read_sequence_file;

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
    #[serde(skip_serializing_if = "RulePlans::is_empty")]
    rule_plans: RulePlans,
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
            rule_plans: RulePlans::default(),
            task_registration: None,
        }
    }
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
        let Some(path) = api_scope_path(&self.scope) else {
            return Ok(());
        };
        let catalog = ApiCatalog::load(&target.join(api_catalog::PATH))?.unwrap_or_default();
        let patterns = catalog.case_paths();
        let pattern = catalog
            .routes()
            .contains_key(path)
            .then_some(path)
            .or_else(|| api_catalog::matching_case_pattern(&patterns, path))
            .context("ownership API must match the committed case catalog")?;
        let group = &catalog.routes()[pattern];
        ensure!(self.group == *group, "use the catalog API group {group}");
        self.scope = format!("api:{pattern}");
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
    pub lookahead: Option<Vec<WindowFinding>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Candidate {
    attempt_id: Uuid,
    commit: String,
    included_fixes: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    included_rule_plans: BTreeSet<String>,
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
    Claim(Claim),
    Confirmed(Confirmation),
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
        #[serde(default)]
        included_rule_plans: BTreeSet<String>,
        #[serde(default)]
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
        task.action(self.registration(task))
    }

    pub fn require_task_delivery(&self, task: &Task, binding: &Registration) -> Result<()> {
        task.require_delivery(self.registration(task), binding)
    }

    fn registration(&self, task: &Task) -> Option<&Registration> {
        if task.is_lookahead() {
            self.window.as_ref()?.registration.as_ref()
        } else {
            self.task_registration.as_ref()
        }
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
            failure.seq == seq
                && attempt_uuid(attempt).ok() == Some(failure.attempt_id)
                && self.window.as_ref().is_some_and(|window| {
                    window.attempt_id == Some(failure.attempt_id) && window.coverage.is_some()
                })
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
        self.rule_plans.retire_incompatible(target, base)?;
        let window = session::dispatch_window(target, recording, seq, 0)?;
        self.observe_window(base, attempt_uuid(attempt)?, seq, window)
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
        self.assign_linked(&owner, base);
        Ok(())
    }

    fn enqueue_owner(&mut self, owner: &Ownership, base: &str) {
        if !self.failure_was_applied(owner.seq)
            && !self.groups.pending(&owner.group, owner.seq)
            && !self.ready_rule_covers(&owner.group, owner.seq)
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
        let priority = self.failure.as_ref().and_then(|failure| {
            self.owners
                .get(&failure.seq.to_string())
                .map(|owner| owner.group.as_str())
        });
        self.groups
            .reserve(self.max_implementers, priority, allocate)
    }

    pub fn clear_runtime_handles(&mut self) {
        self.groups.clear_worker_handles();
        self.task_registration = None;
        if let Some(window) = self.window.as_mut() {
            window.registration = None;
        }
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
        if let Some(progress) = self.read_window_progress() {
            action["details"]["window"] = progress;
        }
        let integration = action["details"]["task"]["requirement"] == "integration_required";
        if integration {
            action["details"]["task"]["ready_fixes"] = json!(self.groups.ready_fixes().count());
            let plan_count = self.rule_plans.pending().count();
            if plan_count > 0 {
                action["details"]["task"]["ready_rule_plans"] = json!(plan_count);
            }
        }
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
                action["details"]["fixes"] = json!(
                    self.groups
                        .ready_fixes()
                        .map(fix_summary)
                        .collect::<Vec<_>>()
                );
                let plans = self.rule_plans.summaries();
                if !plans.is_empty() {
                    action["details"]["rule_plans"] = json!(plans);
                }
            }
        }
        action
    }

    pub fn implementation_action(&self) -> Value {
        let (kind, summary) = if self.groups.has_active_assignments() {
            (
                "implementation_required",
                "Follow the registered implementers and submit confirmations and completed repairs.",
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
        if let Some(blocker) = self.coverage_blocker() {
            return blocker;
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
        self.window.is_some()
            || self.groups.has_lookahead_work()
            || self.rule_plans.pending().next().is_some()
    }

    pub fn retire_lookahead_work(&mut self) {
        self.window = None;
        self.groups.retire_lookahead_work();
        self.rule_plans.retire_pending();
    }

    pub fn validate_delivery_sequences(
        &self,
        group: &str,
        id: Uuid,
        sequences: &BTreeSet<u64>,
    ) -> Result<&str> {
        self.groups
            .validate_delivery_sequences(group, id, sequences)
    }

    pub fn consume_rule_sequences(&mut self, group: &str, sequences: &BTreeSet<u64>) {
        self.groups.consume_lookahead(group, sequences);
    }

    pub fn ready_integration(&self, owner: Option<&Ownership>) -> Option<usize> {
        if owner.is_some() && !self.window_ready() {
            return None;
        }
        let ready = self.groups.ready_fixes().count() + self.rule_plans.pending().count();
        (ready > 0).then_some(ready)
    }

    pub fn candidate_commit(&self, attempt: &E2eEventSessionResult) -> Option<&str> {
        if self
            .window
            .as_ref()
            .is_some_and(|window| window.attempt_id == attempt_uuid(attempt).ok())
            && (!self.window_ready() || self.window_changes_ready())
        {
            return None;
        }
        self.previous_candidate(attempt)
    }

    pub(super) fn previous_candidate(&self, attempt: &E2eEventSessionResult) -> Option<&str> {
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
                let registration = if task.is_lookahead() {
                    &mut self
                        .window
                        .as_mut()
                        .context("no active lookahead window")?
                        .registration
                } else {
                    &mut self.task_registration
                };
                task.register(
                    registration,
                    Registration {
                        task_id,
                        agent_handle,
                    },
                    state,
                )?;
                Ok(Vec::new())
            }
            Receipt::Implementers { workers } => {
                let exited: Vec<_> = workers
                    .iter()
                    .filter_map(|worker| worker.exited_group().map(str::to_owned))
                    .collect();
                self.groups.update_implementers(workers)?;
                for group in exited {
                    let planned = self
                        .rule_plans
                        .pending()
                        .filter(|plan| plan.group() == group)
                        .flat_map(|plan| plan.sequences().iter().copied())
                        .collect();
                    self.groups.consume_lookahead(&group, &planned);
                }
                Ok(Vec::new())
            }
            Receipt::Claim(claim) => {
                self.claim(claim)?;
                Ok(Vec::new())
            }
            Receipt::Confirmed(confirmation) => {
                self.confirm(confirmation)?;
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
                self.require_confirmed_review(&sequences)?;
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
                included_rule_plans,
                checks,
            } => {
                let attempt =
                    attempt.context("publish a candidate for a finished Replay attempt")?;
                let task = Task::integration(
                    &attempt.run_key,
                    &attempt.attempt_id,
                    self.groups.ready_fixes().count() + self.rule_plans.pending().count(),
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
                        included_rule_plans,
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
        if !candidate.checks.is_empty() {
            validate_checks(&candidate.checks)?;
        }
        let previous = self
            .previous_candidate(attempt)
            .or(attempt.target_commit.as_deref())
            .context("attempt lacks Target identity")?;
        ensure!(
            previous != head && is_ancestor(root, previous, head)?,
            "candidate must advance the Target revision {previous}"
        );
        if seq.is_some() {
            self.require_window_candidate(&candidate)?;
        }
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
            !ready.is_empty() || !candidate.included_rule_plans.is_empty(),
            "candidate must include an accepted delivery"
        );
        if !candidate.included_rule_plans.is_empty() {
            let policy = self
                .rule_plans
                .render(root, previous, &candidate.included_rule_plans)?;
            ensure!(
                rule_plans::committed_policy(root, head, &policy.path)? == policy.rendered,
                "candidate policy does not match the selected Session rule plans"
            );
        }
        api_grouping::validate_committed_catalog(
            root,
            self.groups.api_work_for(&candidate.included_fixes),
        )?;
        if let Some(coverage) = self
            .window
            .as_mut()
            .and_then(|window| window.coverage.as_mut())
        {
            coverage.mark_applied(ready.iter().flat_map(|fix| fix.sequences.iter().copied()));
        }
        let completed = self.groups.mark_integrated(&candidate.included_fixes);
        for (group, sequences) in self
            .rule_plans
            .mark_integrated(&candidate.included_rule_plans)
        {
            self.consume_rule_sequences(&group, &sequences);
            if let Some(coverage) = self
                .window
                .as_mut()
                .and_then(|window| window.coverage.as_mut())
            {
                coverage.mark_applied(sequences);
            }
        }
        self.candidate = Some(candidate);
        Ok(completed)
    }
}

fn fix_summary(fix: &Fix) -> Value {
    if fix.sequences.len() <= 32 {
        return json!(fix);
    }
    json!({
        "group": fix.group,
        "assignment_id": fix.assignment_id.simple().to_string(),
        "commit": fix.commit,
        "sequence_count": fix.sequences.len(),
        "checks": fix.checks
    })
}

fn attempt_uuid(attempt: &E2eEventSessionResult) -> Result<Uuid> {
    Ok(attempt.attempt_id.parse()?)
}

fn validate_scope(scope: &str) -> Result<()> {
    let is_api = api_scope_path(scope).is_some();
    let is_job = scope
        .strip_prefix("job:")
        .is_some_and(|name| !name.is_empty() && !name.contains(char::is_whitespace));
    ensure!(
        is_api || is_job || matches!(scope, "startup" | "shutdown"),
        "scope must be api:/case/pattern, job:NAME, startup, or shutdown"
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
