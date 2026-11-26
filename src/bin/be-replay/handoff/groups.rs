//! Worktree reservations and sequenced deliveries for each implementation group.
use std::{
    collections::{BTreeMap, BTreeSet},
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

    pub(super) fn reserve(
        &mut self,
        max: usize,
        mut allocate: impl FnMut() -> Result<usize>,
    ) -> Result<()> {
        let available = max.saturating_sub(self.active_slots().count());
        for group in self
            .work
            .values_mut()
            .filter(|group| group.assignment.is_none() && !group.items.is_empty())
            .take(available)
        {
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
                        "base_commit": work.base_commit, "items": work.items,
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

    pub(super) fn accept_fixes(&mut self, root: &Path, fixes: Vec<Fix>) -> Result<()> {
        ensure!(
            !fixes.is_empty(),
            "fixes receipt must include an accepted repair"
        );
        let mut fresh = BTreeMap::<(&str, &str), usize>::new();
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
            let work = self.active(&fix.group, fix.assignment_id)?;
            validate_sequences(&fix.sequences)?;
            validate_checks(&fix.checks)?;
            validate_commit(root, &fix.commit)?;
            ensure!(
                fix.commit != work.base_commit
                    && is_ancestor(root, &work.base_commit, &fix.commit)?,
                "delivery {} must advance assignment base {}",
                fix.group,
                work.base_commit
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
        ensure!(
            review.sequences.iter().all(|seq| {
                work.reviewed.values().any(|prior| prior.contains(seq))
                    || work.items.iter().any(|item| {
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
        self.active(&gap.group, gap.assignment_id)?;
        validate_sequences(&gap.sequences)?;
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
            || self.gaps.iter().any(|reported| {
                reported
                    .gap
                    .sequences
                    .iter()
                    .any(|seq| !reported.dismissed.contains(seq))
            })
    }

    pub(super) fn retire_lookahead_work(&mut self) {
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
    fn validate_assignment(&self, group: &str, assignment_id: Uuid) -> Result<()> {
        ensure!(
            self.assignment
                .as_ref()
                .is_some_and(|assignment| assignment.id == assignment_id),
            "delivery does not match the active assignment for group {group}"
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
mod tests {
    use super::*;

    fn item(scope: &str, sequences: &[u64]) -> WorkItem {
        WorkItem {
            scope: scope.to_owned(),
            sequences: sequences.iter().copied().collect(),
            apis: Vec::new(),
        }
    }

    #[test]
    fn an_unconfirmed_or_expired_worker_requires_a_runtime_check() {
        let now = Utc::now();
        let mut assignment = Assignment {
            id: Uuid::new_v4(),
            slot: 0,
            agent_handle: Some("actual-handle".into()),
            running_reported_at: None,
        };
        assert!(assignment.needs_worker_status(now));
        assignment.running_reported_at = Some(now);
        assert!(!assignment.needs_worker_status(now));
        assert!(assignment.needs_worker_status(now + WORKER_STATUS_TTL));
        assignment.agent_handle = None;
        assert!(!assignment.needs_worker_status(now));
    }

    #[test]
    fn overlapping_windows_keep_one_assignment_and_can_reopen_a_failed_sequence() {
        let mut groups = Groups::default();
        let scope = "api:GET /things";
        groups.enqueue("things", item(scope, &[11, 13]), "base");
        groups.reserve(1, || Ok(4)).unwrap();
        let lease = groups.work["things"].assignment.as_ref().unwrap().id;
        groups.enqueue("things", item(scope, &[13, 17]), "later");
        groups.enqueue("workers", item("job:refresh", &[19]), "later");
        groups
            .reserve(1, || panic!("only one slot is available"))
            .unwrap();

        let assigned = groups.assignments();
        assert_eq!(assigned[0]["name"], "api-implementer-4");
        assert_eq!(assigned[0]["base_commit"], "base");
        assert_eq!(assigned[0]["assignment_id"], lease.simple().to_string());
        assert_eq!(assigned[0]["items"][0]["sequences"], json!([11, 13, 17]));

        groups
            .review(
                "things",
                lease,
                [11, 13].into(),
                vec!["checks".into()],
                None,
            )
            .unwrap();
        groups.enqueue("things", item(scope, &[11, 13, 17]), "later");
        assert!(!groups.pending("things", 13));
        groups.reopen("things", item(scope, &[13]), "later");
        assert!(groups.pending("things", 13));
        assert_eq!(groups.active_slots().collect::<Vec<_>>(), [4]);
        groups
            .review(
                "things",
                lease,
                [13, 17].into(),
                vec!["checks".into()],
                None,
            )
            .unwrap();
        groups.reserve(1, || Ok(5)).unwrap();
        assert_eq!(groups.assignments()[0]["group"], "workers");
    }

    #[test]
    fn unchanged_lookahead_cannot_discharge_api_implementation() {
        let mut groups = Groups::default();
        let scope = "api:GET /things";
        let mut implementation = item(scope, &[11]);
        implementation.apis.push(ApiConfirmation {
            api: "GET /things".to_owned(),
            implemented: false,
            case_pattern: Some("/things".to_owned()),
            group: Some("things".to_owned()),
        });
        groups.enqueue("things", implementation, "base");
        groups.enqueue("things", item(scope, &[11, 13]), "base");
        groups.reserve(1, || Ok(0)).unwrap();
        let lease = groups.work["things"].assignment.as_ref().unwrap().id;
        groups
            .review(
                "things",
                lease,
                [11, 13].into(),
                vec!["checks".into()],
                None,
            )
            .unwrap();
        let assigned = groups.assignments();
        assert_eq!(assigned[0]["items"][0]["sequences"], json!([11]));
        assert_eq!(assigned[0]["items"].as_array().unwrap().len(), 1);
        assert!(groups.has_pending_api_work());
    }

    #[test]
    fn released_assignment_ids_cannot_claim_new_group_work() {
        let mut groups = Groups::default();
        let scope = "api:GET /things";
        groups.enqueue("things", item(scope, &[11]), "base");
        groups.reserve(1, || Ok(4)).unwrap();
        let lease = groups.work["things"].assignment.as_ref().unwrap().id;
        groups
            .review("things", lease, [11].into(), vec!["checks".into()], None)
            .unwrap();
        groups.enqueue("things", item(scope, &[13]), "base");
        groups.reserve(1, || Ok(4)).unwrap();
        let new_lease = groups.work["things"].assignment.as_ref().unwrap().id;
        assert_ne!(new_lease, lease);
        groups
            .review("things", lease, [11].into(), vec!["checks".into()], None)
            .unwrap();
        assert!(
            groups
                .review("things", lease, [13].into(), vec!["checks".into()], None)
                .is_err()
        );
        assert!(
            groups
                .accept_gap(Gap {
                    group: "things".to_owned(),
                    assignment_id: lease,
                    sequences: [13].into(),
                    evidence: "stale".to_owned(),
                })
                .is_err()
        );
        assert!(groups.pending("things", 13));
    }

    #[test]
    fn passing_replay_retires_window_work_but_keeps_required_apis() {
        let mut groups = Groups::default();
        let mut implementation = item("api:GET /things", &[11]);
        implementation.apis.push(ApiConfirmation {
            api: "GET /things".to_owned(),
            implemented: false,
            case_pattern: Some("/things".to_owned()),
            group: Some("things".to_owned()),
        });
        groups.enqueue("things", implementation, "base");
        groups.enqueue("things", item("api:GET /things", &[13]), "base");
        groups.enqueue("users", item("api:GET /users", &[15]), "base");
        let mut slots = 0..;
        groups.reserve(2, || Ok(slots.next().unwrap())).unwrap();
        let lease = groups.work["things"].assignment.as_ref().unwrap().id;

        assert!(groups.has_lookahead_work());
        groups.retire_lookahead_work();
        assert!(!groups.has_lookahead_work());
        assert!(groups.has_pending_api_work());
        assert!(groups.pending("things", 11));
        assert!(!groups.pending("things", 13));
        assert!(!groups.pending("users", 15));
        assert_eq!(groups.work["things"].assignment.as_ref().unwrap().id, lease);
        assert_eq!(groups.active_slots().collect::<Vec<_>>(), [0]);
    }
}
