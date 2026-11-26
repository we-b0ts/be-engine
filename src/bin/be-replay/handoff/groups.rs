//! Worktree reservations and sequenced deliveries for each implementation group.
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::RangeInclusive,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use traffic_e2e::{
    event_work::ApiConfirmation, repository::implementer_worktree, session::RecordedApi,
};
use uuid::Uuid;

use super::{ApiBacklog, api_backlog, api_grouping, is_ancestor, validate_checks, validate_commit};

const WORKER_STATUS_TTL: TimeDelta = TimeDelta::hours(1);
pub(super) const INLINE_SEQUENCE_LIMIT: usize = 32;

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Groups {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    work: BTreeMap<String, Group>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fixes: Vec<AcceptedFix>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    gaps: Vec<ReportedGap>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Group {
    base_commit: String,
    assignment: Option<Assignment>,
    items: Vec<WorkItem>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    reviewed: BTreeMap<String, BTreeSet<u64>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reviews: Vec<Review>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Assignment {
    id: Uuid,
    slot: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    running_reported_at: Option<DateTime<Utc>>,
}

impl Assignment {
    fn needs_worker_status(&self, now: DateTime<Utc>) -> bool {
        self.agent_handle.is_some()
            && !self.running_reported_at.is_some_and(|reported| {
                let age = now - reported;
                age >= TimeDelta::zero() && age < WORKER_STATUS_TTL
            })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImplementerUpdate {
    group: String,
    assignment_id: Uuid,
    agent_handle: String,
    state: ImplementerState,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ImplementerState {
    Started,
    Running,
    Exited,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Review {
    assignment_id: Uuid,
    sequences: BTreeSet<u64>,
    checks: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    confirms_apis: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WorkItem {
    pub scope: String,
    pub sequences: BTreeSet<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apis: Vec<ApiConfirmation>,
}

impl WorkItem {
    fn handoff(&self) -> Value {
        let mut row = json!({"scope": self.scope, "sequence_count": self.sequences.len()});
        if self.sequences.len() <= INLINE_SEQUENCE_LIMIT {
            row["sequences"] = json!(self.sequences);
        }
        if !self.apis.is_empty() {
            row["apis"] = json!(self.apis);
        }
        row
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fix {
    pub group: String,
    #[serde(with = "uuid::serde::simple")]
    pub assignment_id: Uuid,
    pub commit: String,
    pub sequences: BTreeSet<u64>,
    pub checks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AcceptedFix {
    fix: Fix,
    integrated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    apis: Vec<ApiConfirmation>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Gap {
    pub group: String,
    #[serde(with = "uuid::serde::simple")]
    pub assignment_id: Uuid,
    pub sequences: BTreeSet<u64>,
    pub evidence: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReportedGap {
    gap: Gap,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    dismissed: BTreeSet<u64>,
}

impl Groups {
    pub(super) fn open_apis(&self) -> impl Iterator<Item = &ApiConfirmation> {
        self.work
            .values()
            .flat_map(|work| work.items.iter().flat_map(|item| &item.apis))
            .chain(
                self.fixes
                    .iter()
                    .filter(|fix| !fix.integrated)
                    .flat_map(|fix| &fix.apis),
            )
    }

    pub(super) fn refresh_api_work(
        &mut self,
        inventory: &[RecordedApi],
        backlog: &ApiBacklog,
        base: &str,
    ) {
        let pending: BTreeMap<_, _> = inventory
            .iter()
            .filter_map(|api| {
                let group = api.group.as_deref()?;
                backlog
                    .pending(&api.api)
                    .then_some(((group, api.api.as_str()), api))
            })
            .collect();
        for (group, work) in &mut self.work {
            work.items.retain(|item| {
                item.apis.is_empty()
                    || item
                        .scope
                        .strip_prefix("api:")
                        .is_some_and(|label| pending.contains_key(&(group.as_str(), label)))
            });
            work.release_empty_assignment();
        }
        for fix in self.fixes.iter_mut().filter(|fix| !fix.integrated) {
            fix.apis.retain(|api| backlog.pending_api(api));
        }
        for ((group, label), api) in pending {
            let scope = format!("api:{label}");
            let assigned = self.work.get(group).is_some_and(|work| {
                work.items
                    .iter()
                    .any(|item| !item.apis.is_empty() && item.scope == scope)
            });
            let delivered = self.fixes.iter().any(|fix| {
                !fix.integrated
                    && fix.fix.group == group
                    && fix.apis.iter().any(|row| {
                        api_backlog::identity(row).is_some_and(|(method, pattern)| {
                            api.method == method && api.case_pattern.as_deref() == Some(pattern)
                        })
                    })
            });
            if !assigned && !delivered {
                if let Some(work) = self.work.get_mut(group) {
                    work.refresh_dispatch_base(base);
                }
                self.enqueue(
                    group,
                    WorkItem {
                        scope,
                        sequences: [api.first_seq].into(),
                        apis: vec![ApiConfirmation {
                            api: api.api.clone(),
                            implemented: false,
                            case_pattern: api.case_pattern.clone(),
                            group: api.group.clone(),
                        }],
                    },
                    base,
                );
            }
        }
    }

    pub(super) fn enqueue(&mut self, group: &str, mut item: WorkItem, base: &str) {
        let work = self.work.entry(group.to_owned()).or_insert_with(|| Group {
            base_commit: base.to_owned(),
            assignment: None,
            items: Vec::new(),
            reviewed: BTreeMap::new(),
            reviews: Vec::new(),
        });
        if item.apis.is_empty()
            && let Some(reviewed) = work.reviewed.get(&item.scope)
        {
            item.sequences.retain(|seq| !reviewed.contains(seq));
        }
        if item.sequences.is_empty() {
            return;
        }
        if work.items.is_empty() {
            base.clone_into(&mut work.base_commit);
        }
        if let Some(existing) = work
            .items
            .iter_mut()
            .find(|existing| existing.scope == item.scope && existing.apis == item.apis)
        {
            existing.sequences.extend(item.sequences);
        } else {
            work.items.push(item);
        }
    }

    pub(super) fn reopen(&mut self, group: &str, item: WorkItem, base: &str) {
        if let Some(reviewed) = self
            .work
            .get_mut(group)
            .and_then(|work| work.reviewed.get_mut(&item.scope))
        {
            reviewed.retain(|seq| !item.sequences.contains(seq));
        }
        self.enqueue(group, item, base);
    }

    pub(super) fn retain_lookahead(&mut self, bounds: RangeInclusive<u64>) {
        for work in self.work.values_mut() {
            work.items.retain_mut(|item| {
                if !item.apis.is_empty() {
                    return true;
                }
                item.sequences.retain(|seq| bounds.contains(seq));
                !item.sequences.is_empty()
            });
        }
    }

    pub(super) fn release_empty_lookahead_assignments(&mut self) {
        for work in self.work.values_mut() {
            work.release_empty_assignment();
        }
    }

    pub(super) fn reserve(
        &mut self,
        max: usize,
        priority: Option<&str>,
        mut allocate: impl FnMut() -> Result<usize>,
    ) -> Result<()> {
        let available = max.saturating_sub(self.active_slots().count());
        let mut pending = self
            .work
            .iter_mut()
            .filter(|(_, group)| group.assignment.is_none() && !group.items.is_empty())
            .collect::<Vec<_>>();
        pending.sort_by_key(|(name, _)| Some(name.as_str()) != priority);
        for (_, group) in pending.into_iter().take(available) {
            group.assignment = Some(Assignment {
                id: Uuid::new_v4(),
                slot: allocate()?,
                agent_handle: None,
                running_reported_at: None,
            });
        }
        Ok(())
    }

    pub(super) fn active_slots(&self) -> impl Iterator<Item = usize> + '_ {
        self.work
            .values()
            .filter_map(|group| group.assignment.as_ref().map(|assignment| assignment.slot))
    }

    pub(super) fn has_active_assignments(&self) -> bool {
        self.active_slots().next().is_some()
    }

    pub(super) fn pending_dispatch(&self) -> usize {
        self.work
            .values()
            .filter_map(|group| group.assignment.as_ref())
            .filter(|assignment| assignment.agent_handle.is_none())
            .count()
    }

    pub(super) fn pending_worker_status(&self) -> usize {
        let now = Utc::now();
        self.work
            .values()
            .filter_map(|group| group.assignment.as_ref())
            .filter(|assignment| assignment.needs_worker_status(now))
            .count()
    }

    pub(super) fn needs_api_dispatch(&self) -> bool {
        let now = Utc::now();
        self.work.values().any(|work| {
            work.items.iter().any(|item| !item.apis.is_empty())
                && work.assignment.as_ref().is_none_or(|assignment| {
                    assignment.agent_handle.is_none() || assignment.needs_worker_status(now)
                })
        })
    }

    pub(super) fn queued_api_groups(&self) -> usize {
        self.work
            .values()
            .filter(|group| {
                group.assignment.is_none() && group.items.iter().any(|item| !item.apis.is_empty())
            })
            .count()
    }

    pub(super) fn clear_worker_handles(&mut self) {
        for assignment in self
            .work
            .values_mut()
            .filter_map(|group| group.assignment.as_mut())
        {
            assignment.agent_handle = None;
            assignment.running_reported_at = None;
        }
    }

    pub(super) fn update_implementers(&mut self, workers: Vec<ImplementerUpdate>) -> Result<()> {
        ensure!(!workers.is_empty(), "report at least one implementer");
        let mut groups = BTreeSet::new();
        for worker in workers {
            ensure!(
                groups.insert(worker.group.clone()),
                "duplicate implementer report for group {}",
                worker.group
            );
            ensure!(
                !worker.agent_handle.trim().is_empty()
                    && worker.agent_handle.len() <= 4096
                    && !worker.agent_handle.chars().any(char::is_control),
                "invalid implementer agent_handle"
            );
            self.active(&worker.group, worker.assignment_id)?;
            if worker.state == ImplementerState::Started {
                ensure!(
                    !self
                        .work
                        .values()
                        .filter_map(|group| group.assignment.as_ref())
                        .any(|assignment| assignment.id != worker.assignment_id
                            && assignment.agent_handle.as_ref() == Some(&worker.agent_handle)),
                    "implementer agent_handle already belongs to another assignment"
                );
            }
            let assignment = self
                .work
                .get_mut(&worker.group)
                .and_then(|group| group.assignment.as_mut())
                .expect("validated assignment");
            ensure!(
                assignment
                    .agent_handle
                    .as_ref()
                    .is_none_or(|handle| handle == &worker.agent_handle),
                "report the current implementer handle exiting before replacing it for group {}",
                worker.group
            );
            match worker.state {
                ImplementerState::Started => assignment.agent_handle = Some(worker.agent_handle),
                ImplementerState::Running => {
                    ensure!(
                        assignment.agent_handle.is_some(),
                        "register the implementer handle before reporting it running"
                    );
                    assignment.running_reported_at = Some(Utc::now());
                }
                ImplementerState::Exited => {
                    assignment.agent_handle = None;
                    assignment.running_reported_at = None;
                }
            }
        }
        Ok(())
    }

    pub(super) fn pending(&self, group: &str, seq: u64) -> bool {
        self.work
            .get(group)
            .is_some_and(|work| work.items.iter().any(|item| item.sequences.contains(&seq)))
    }

    pub(super) fn assignments(&self) -> Value {
        let now = Utc::now();
        json!(
            self.work
                .iter()
                .filter_map(|(group, work)| {
                    let assignment = work.assignment.as_ref()?;
                    let slot = assignment.slot;
                    let name = format!("api-implementer-{slot}");
                    let worktree = implementer_worktree(Path::new(""), slot);
                    let mut row = json!({
                        "group": group, "name": name, "worktree": worktree,
                        "assignment_id": assignment.id.simple().to_string(),
                        "base_commit": work.base_commit,
                        "items": work.items.iter().map(WorkItem::handoff).collect::<Vec<_>>(),
                    });
                    if let Some(handle) = &assignment.agent_handle {
                        row["agent_handle"] = json!(handle);
                        row["worker_status"] = json!(if assignment.needs_worker_status(now) {
                            "check_required"
                        } else {
                            "running"
                        });
                    }
                    Some(row)
                })
                .collect::<Vec<_>>()
        )
    }

    pub(super) fn assignment_sequences(
        &self,
        id: Uuid,
        scope: Option<&str>,
    ) -> Result<BTreeSet<u64>> {
        let work = self
            .work
            .values()
            .find(|work| {
                work.assignment
                    .as_ref()
                    .is_some_and(|assignment| assignment.id == id)
            })
            .context("no active assignment with that ID; inspect status")?;
        Ok(work
            .items
            .iter()
            .filter(|item| scope.is_none_or(|scope| item.scope == scope))
            .flat_map(|item| item.sequences.iter().copied())
            .collect())
    }

    pub(super) fn validate_delivery_sequences(
        &self,
        group: &str,
        id: Uuid,
        sequences: &BTreeSet<u64>,
    ) -> Result<&str> {
        let work = self.active(group, id)?;
        work.require_worker(group)?;
        work.require_sequences(group, sequences)?;
        Ok(&work.base_commit)
    }

    pub(super) fn assignment_base(&self, group: &str, id: Uuid) -> Result<&str> {
        let work = self.active(group, id)?;
        work.require_worker(group)?;
        Ok(&work.base_commit)
    }

    pub(super) fn consume_lookahead(&mut self, group: &str, sequences: &BTreeSet<u64>) {
        if let Some(work) = self.work.get_mut(group) {
            work.consume(sequences, false);
        }
    }

    pub(super) fn accept_fixes(&mut self, root: &Path, fixes: Vec<Fix>) -> Result<()> {
        ensure!(
            !fixes.is_empty(),
            "fixes receipt must include an accepted repair"
        );
        let mut fresh = BTreeMap::<(&str, &str), usize>::new();
        let mut covered = BTreeSet::new();
        for (index, fix) in fixes.iter().enumerate() {
            let key = (fix.group.as_str(), fix.commit.as_str());
            let previous = self
                .fixes
                .iter()
                .find(|accepted| {
                    accepted.fix.group == fix.group && accepted.fix.commit == fix.commit
                })
                .map(|accepted| &accepted.fix)
                .or_else(|| fresh.get(&key).map(|&i| &fixes[i]));
            if let Some(previous) = previous {
                ensure!(
                    previous == fix,
                    "a different delivery exists for {} at {}",
                    fix.group,
                    fix.commit
                );
                continue;
            }
            let base =
                self.validate_delivery_sequences(&fix.group, fix.assignment_id, &fix.sequences)?;
            ensure!(
                fix.sequences
                    .iter()
                    .all(|seq| covered.insert((fix.assignment_id, seq))),
                "the fixes receipt claims a sequence twice for group {}",
                fix.group
            );
            validate_checks(&fix.checks)?;
            validate_commit(root, &fix.commit)?;
            ensure!(
                fix.commit != base && is_ancestor(root, base, &fix.commit)?,
                "delivery {} must advance assignment base {}",
                fix.group,
                base
            );
            fresh.insert(key, index);
        }
        let fresh: BTreeSet<_> = fresh.into_values().collect();
        for (index, fix) in fixes.into_iter().enumerate() {
            if fresh.contains(&index) {
                let work = self
                    .work
                    .get_mut(&fix.group)
                    .expect("validated active group");
                let apis = work.consume(&fix.sequences, true);
                self.fixes.push(AcceptedFix {
                    fix,
                    integrated: false,
                    apis,
                });
            }
        }
        Ok(())
    }

    pub(super) fn review(
        &mut self,
        group: &str,
        assignment_id: Uuid,
        sequences: BTreeSet<u64>,
        checks: Vec<String>,
        api_catalog_root: Option<&Path>,
    ) -> Result<Vec<ApiConfirmation>> {
        validate_sequences(&sequences)?;
        validate_checks(&checks)?;
        let review = Review {
            assignment_id,
            sequences,
            checks,
            confirms_apis: api_catalog_root.is_some(),
        };
        let work = self
            .work
            .get_mut(group)
            .with_context(|| format!("unknown implementation group {group}"))?;
        if work.reviews.contains(&review) {
            return Ok(Vec::new());
        }
        work.validate_assignment(group, assignment_id)?;
        work.require_worker(group)?;
        ensure!(
            review.sequences.iter().all(|seq| {
                work.items.iter().any(|item| {
                    (api_catalog_root.is_some() || item.apis.is_empty())
                        && item.sequences.contains(seq)
                })
            }),
            "no-change review must refer to assigned sequences in {group} and explicitly confirm any API work"
        );
        if let Some(root) = api_catalog_root {
            api_grouping::validate_committed_catalog(
                root,
                work.items
                    .iter()
                    .filter(|item| !item.sequences.is_disjoint(&review.sequences))
                    .flat_map(|item| &item.apis),
            )?;
        }
        let completed = work.consume(&review.sequences, api_catalog_root.is_some());
        work.reviews.push(review);
        Ok(completed)
    }

    pub(super) fn accept_gap(&mut self, gap: Gap) -> Result<()> {
        if self.gaps.iter().any(|reported| reported.gap == gap) {
            return Ok(());
        }
        self.validate_delivery_sequences(&gap.group, gap.assignment_id, &gap.sequences)?;
        ensure!(
            !gap.evidence.trim().is_empty(),
            "engine gap requires evidence"
        );
        self.gaps.push(ReportedGap {
            gap,
            dismissed: BTreeSet::new(),
        });
        Ok(())
    }

    pub(super) fn ready_fixes(&self) -> impl Iterator<Item = &Fix> {
        self.fixes
            .iter()
            .filter(|accepted| !accepted.integrated)
            .map(|accepted| &accepted.fix)
    }

    pub(super) fn gap(&self, group: &str, seq: u64) -> Option<&Gap> {
        self.gaps
            .iter()
            .rev()
            .find(|reported| {
                reported.gap.group == group
                    && reported.gap.sequences.contains(&seq)
                    && !reported.dismissed.contains(&seq)
            })
            .map(|reported| &reported.gap)
    }

    pub(super) fn dismiss_gap(&mut self, group: &str, seq: u64) {
        for reported in &mut self.gaps {
            if reported.gap.group == group && reported.gap.sequences.contains(&seq) {
                reported.dismissed.insert(seq);
            }
        }
    }

    pub(super) fn api_work_for<'a>(
        &'a self,
        commits: &'a BTreeSet<String>,
    ) -> impl Iterator<Item = &'a ApiConfirmation> {
        self.fixes
            .iter()
            .filter(|accepted| commits.contains(&accepted.fix.commit))
            .flat_map(|accepted| &accepted.apis)
    }

    pub(super) fn mark_integrated(&mut self, commits: &BTreeSet<String>) -> Vec<ApiConfirmation> {
        let mut completed = Vec::new();
        for accepted in &mut self.fixes {
            if !accepted.integrated && commits.contains(&accepted.fix.commit) {
                accepted.integrated = true;
                completed.extend(accepted.apis.iter().cloned());
            }
        }
        completed
    }

    pub(super) fn has_pending_api_work(&self) -> bool {
        self.work
            .values()
            .any(|work| work.items.iter().any(|item| !item.apis.is_empty()))
            || self
                .fixes
                .iter()
                .any(|fix| !fix.integrated && !fix.apis.is_empty())
    }

    pub(super) fn has_lookahead_work(&self) -> bool {
        self.work
            .values()
            .any(|work| work.items.iter().any(|item| item.apis.is_empty()))
            || self
                .fixes
                .iter()
                .any(|fix| !fix.integrated && fix.apis.is_empty())
            || self.gaps.iter().any(|reported| {
                reported
                    .gap
                    .sequences
                    .iter()
                    .any(|seq| !reported.dismissed.contains(seq))
            })
    }

    pub(super) fn retire_lookahead_work(&mut self) {
        self.fixes
            .retain(|fix| fix.integrated || !fix.apis.is_empty());
        for work in self.work.values_mut() {
            work.items.retain(|item| {
                if item.apis.is_empty() {
                    work.reviewed
                        .entry(item.scope.clone())
                        .or_default()
                        .extend(&item.sequences);
                    false
                } else {
                    true
                }
            });
            work.release_empty_assignment();
        }
        for reported in &mut self.gaps {
            reported.dismissed.extend(&reported.gap.sequences);
        }
    }

    fn active(&self, group: &str, assignment_id: Uuid) -> Result<&Group> {
        let work = self
            .work
            .get(group)
            .with_context(|| format!("unknown implementation group {group}"))?;
        work.validate_assignment(group, assignment_id)?;
        Ok(work)
    }
}

impl Group {
    fn require_sequences(&self, group: &str, sequences: &BTreeSet<u64>) -> Result<()> {
        validate_sequences(sequences)?;
        if let Some(seq) = sequences
            .iter()
            .find(|seq| !self.items.iter().any(|item| item.sequences.contains(seq)))
        {
            anyhow::bail!("seq {seq} is not assigned to group {group}");
        }
        Ok(())
    }

    fn refresh_dispatch_base(&mut self, base: &str) {
        if let Some(assignment) = &mut self.assignment {
            if assignment.agent_handle.is_some() {
                assignment.running_reported_at = None;
                return;
            }
            if self.base_commit != base {
                assignment.id = Uuid::new_v4();
            }
        }
        base.clone_into(&mut self.base_commit);
    }

    fn validate_assignment(&self, group: &str, assignment_id: Uuid) -> Result<()> {
        ensure!(
            self.assignment
                .as_ref()
                .is_some_and(|assignment| assignment.id == assignment_id),
            "delivery does not match the active assignment for group {group}"
        );
        Ok(())
    }

    fn require_worker(&self, group: &str) -> Result<()> {
        ensure!(
            self.assignment
                .as_ref()
                .is_some_and(|assignment| assignment.agent_handle.is_some()),
            "register the implementer handle before accepting a delivery for group {group}"
        );
        Ok(())
    }

    fn release_empty_assignment(&mut self) {
        if self.items.is_empty() {
            self.assignment = None;
        }
    }

    fn consume(&mut self, sequences: &BTreeSet<u64>, include_apis: bool) -> Vec<ApiConfirmation> {
        let mut apis = Vec::new();
        self.items.retain_mut(|item| {
            if !include_apis && !item.apis.is_empty() {
                return true;
            }
            let reviewed: Vec<_> = item.sequences.intersection(sequences).copied().collect();
            item.sequences.retain(|seq| !sequences.contains(seq));
            if !reviewed.is_empty() {
                self.reviewed
                    .entry(item.scope.clone())
                    .or_default()
                    .extend(reviewed);
            }
            if item.sequences.is_empty() {
                apis.append(&mut item.apis);
                false
            } else {
                true
            }
        });
        self.release_empty_assignment();
        apis
    }
}

fn validate_sequences(sequences: &BTreeSet<u64>) -> Result<()> {
    ensure!(
        !sequences.is_empty() && !sequences.contains(&0),
        "delivery requires positive Source event sequences"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
