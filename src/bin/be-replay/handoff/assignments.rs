//! Assignment reservations and deliveries for Replay findings.
use super::*;

#[derive(Serialize)]
pub(super) struct AcceptedFix<'a> {
    #[serde(with = "uuid::serde::simple")]
    attempt_id: Uuid,
    root_cause: &'a str,
    pub(super) commit: &'a str,
}

#[derive(Serialize)]
pub(super) struct EscalatedGap<'a> {
    #[serde(with = "uuid::serde::simple")]
    attempt_id: Uuid,
    root_cause: &'a str,
    summary: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    evidence: &'a str,
}

#[derive(Serialize)]
pub(super) struct Assignment<'a> {
    group: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worktree: Option<std::path::PathBuf>,
    #[serde(with = "uuid::serde::simple")]
    attempt_id: Uuid,
    base_commit: Option<&'a str>,
    findings: Vec<&'a Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    apis: Vec<&'a ApiConfirmation>,
}

#[derive(Serialize)]
struct AssignmentSummary<'a> {
    group: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worktree: Option<&'a Path>,
    pending: usize,
}

pub(super) fn assignment_rows(assignments: &[Assignment<'_>], detail: AssignmentDetail) -> Value {
    match detail {
        AssignmentDetail::Full => json!(assignments),
        AssignmentDetail::Summary => json!(
            assignments
                .iter()
                .map(|assignment| AssignmentSummary {
                    group: assignment.group,
                    name: assignment.name.as_deref(),
                    worktree: assignment.worktree.as_deref(),
                    pending: assignment.findings.len(),
                })
                .collect::<Vec<_>>()
        ),
    }
}

impl Repair {
    pub(super) fn priority(&self) -> Option<&str> {
        self.first_unmatched.as_deref().or(self.api_work.as_deref())
    }

    pub(super) fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.plan.implementers.iter().chain(&self.plan.waiting)
    }

    pub(super) fn finding(&self, cause: &str) -> Option<&Finding> {
        self.findings().find(|finding| finding.root_cause == cause)
    }

    fn fix(&self, cause: &str) -> Option<&Fix> {
        self.fixes
            .iter()
            .flatten()
            .find(|fix| fix.root_cause == cause)
    }

    pub(super) fn fix_was_integrated(&self, workflow: &Workflow, cause: &str) -> bool {
        self.fix(cause)
            .is_some_and(|fix| workflow.fix_was_integrated(&fix.commit))
    }

    fn is_assigned(&self, cause: &str) -> bool {
        self.plan
            .implementers
            .iter()
            .any(|finding| finding.root_cause == cause)
    }

    fn is_active(&self, cause: &str) -> bool {
        !self.has_delivery(cause)
    }

    pub(super) fn has_delivery(&self, cause: &str) -> bool {
        self.fix(cause).is_some() || self.engine_gaps.contains_key(cause)
    }
}

impl Workflow {
    pub(super) fn accept_fixes(
        &mut self,
        root: &Path,
        attempt_id: Uuid,
        fixes: Vec<Fix>,
    ) -> Result<()> {
        let repair = self
            .assignment_attempt_mut(attempt_id)
            .context("fixes refer to an unknown assignment attempt")?;
        ensure!(
            !fixes.is_empty(),
            "fixes receipt must include an accepted repair"
        );
        let mut causes = BTreeSet::new();
        let mut accepted = Vec::new();
        for fix in fixes {
            ensure!(
                causes.insert(fix.root_cause.clone()),
                "duplicate accepted root cause {}",
                fix.root_cause
            );
            ensure!(
                repair.is_assigned(&fix.root_cause),
                "{} was not assigned for implementation",
                fix.root_cause
            );
            ensure!(
                !repair.engine_gaps.contains_key(&fix.root_cause),
                "{} was already escalated as an engine gap",
                fix.root_cause
            );
            if let Some(previous) = repair.fix(&fix.root_cause) {
                ensure!(
                    previous == &fix,
                    "a delivery is already recorded for {}",
                    fix.root_cause
                );
                continue;
            }
            validate_checks(&fix.checks)?;
            validate_commit(root, &fix.commit)?;
            if let Some(base) = &repair.base_commit {
                ensure!(
                    fix.commit != *base && is_ancestor(root, base, &fix.commit)?,
                    "delivery {} must advance assignment base {base}",
                    fix.root_cause
                );
            }
            accepted.push(fix);
        }
        if !accepted.is_empty() {
            repair.fixes.get_or_insert_with(Vec::new).extend(accepted);
        }
        Ok(())
    }

    pub(super) fn accept_engine_gap(
        &mut self,
        attempt_id: Uuid,
        cause: &str,
        evidence: String,
        reported_during: Uuid,
    ) -> Result<()> {
        let repair = self
            .assignment_attempt_mut(attempt_id)
            .context("engine gap refers to an unknown assignment attempt")?;
        ensure!(
            repair.is_assigned(cause),
            "{cause} was not assigned for implementation"
        );
        ensure!(
            repair.fix(cause).is_none(),
            "{cause} already has an accepted fix"
        );
        ensure!(!evidence.trim().is_empty(), "engine gap requires evidence");
        if let Some(previous) = repair.engine_gaps.get(cause) {
            ensure!(
                previous.evidence == evidence,
                "an engine gap receipt is already recorded for {cause}"
            );
            return Ok(());
        }
        repair.engine_gaps.insert(
            cause.to_owned(),
            EngineGap {
                evidence,
                reported_during,
                retried_on: None,
            },
        );
        Ok(())
    }

    fn assignment_attempt_mut(&mut self, attempt_id: Uuid) -> Option<&mut Repair> {
        self.repair
            .as_mut()
            .filter(|repair| repair.attempt_id == attempt_id)
            .or_else(|| self.earlier.get_mut(&attempt_id))
    }

    pub(super) fn schedule(&self, repair: &Repair, mut findings: Vec<Finding>) -> DispatchPlan {
        let mut plan = DispatchPlan::default();
        let active = self
            .assignments()
            .filter(|(owner, finding)| owner.is_active(&finding.root_cause))
            .collect::<Vec<_>>();
        let mut causes = active
            .iter()
            .map(|(_, finding)| finding.root_cause.as_str())
            .collect::<BTreeSet<_>>();
        let mut groups = active
            .iter()
            .map(|(owner, finding)| (finding.dispatch_group(), owner.attempt_id))
            .collect::<BTreeMap<_, _>>();
        findings.sort_by_key(|finding| Some(finding.root_cause.as_str()) != repair.priority());
        for finding in &findings {
            let cause = finding.root_cause.as_str();
            let group = finding.dispatch_group();
            let owner = groups.get(group);
            if repair.is_assigned(cause) {
                plan.implementers.push(finding.clone());
            } else if owner.map_or(groups.len() >= repair.max_implementers, |id| {
                *id != repair.attempt_id
            }) || causes.contains(cause)
                || self.accepted_fix(cause).is_some()
                || self.gap_for(repair.attempt_id, cause).is_some()
            {
                plan.waiting.push(finding.clone());
            } else {
                causes.insert(cause);
                groups.insert(group, repair.attempt_id);
                plan.implementers.push(finding.clone());
            }
        }
        plan
    }

    pub(super) fn current_assignments(&self, priority: &str) -> Vec<Assignment<'_>> {
        let mut grouped = BTreeMap::new();
        for (owner, finding) in self
            .assignments()
            .filter(|(owner, finding)| owner.is_active(&finding.root_cause))
        {
            let group = finding.dispatch_group();
            let assignment = grouped.entry((owner.attempt_id, group)).or_insert_with(|| {
                let slot = owner.worktrees.get(group).copied();
                Assignment {
                    group,
                    name: slot.map(|slot| format!("api-implementer-{slot}")),
                    worktree: slot.map(|slot| {
                        traffic_e2e::repository::implementer_worktree(Path::new(""), slot)
                    }),
                    attempt_id: owner.attempt_id,
                    base_commit: owner.base_commit.as_deref(),
                    findings: Vec::new(),
                    apis: Vec::new(),
                }
            });
            assignment.findings.push(finding);
            if let Some(api) = self
                .api_review
                .as_ref()
                .and_then(|review| review.tasks.get(&finding.root_cause))
            {
                assignment.apis.extend(&api.apis);
            }
        }
        let mut assignments: Vec<_> = grouped.into_values().collect();
        assignments.sort_by_key(|assignment| {
            !assignment
                .findings
                .iter()
                .any(|finding| finding.root_cause == priority)
        });
        assignments
    }

    pub fn active_worktree_slots(&self) -> impl Iterator<Item = usize> + '_ {
        self.assignments()
            .filter(|(owner, finding)| owner.is_active(&finding.root_cause))
            .filter_map(|(owner, finding)| owner.worktrees.get(finding.dispatch_group()).copied())
    }

    pub fn reserve_worktrees(&mut self, mut allocate: impl FnMut() -> Result<usize>) -> Result<()> {
        for repair in self.earlier.values_mut().chain(self.repair.iter_mut()) {
            let groups: BTreeSet<_> = repair
                .plan
                .implementers
                .iter()
                .filter(|finding| finding.group.is_some() && repair.is_active(&finding.root_cause))
                .map(|finding| finding.dispatch_group().to_owned())
                .collect();
            repair.worktrees.retain(|group, _| groups.contains(group));
            for group in groups {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    repair.worktrees.entry(group)
                {
                    entry.insert(allocate()?);
                }
            }
        }
        Ok(())
    }

    pub(super) fn repairs(&self) -> impl Iterator<Item = &Repair> {
        self.repair.iter().chain(self.earlier.values())
    }

    fn assignments(&self) -> impl Iterator<Item = (&Repair, &Finding)> {
        self.repairs().flat_map(|repair| {
            repair
                .plan
                .implementers
                .iter()
                .map(move |finding| (repair, finding))
        })
    }

    pub(super) fn engine_gap<'a>(
        &'a self,
        repair: &'a Repair,
        cause: &str,
    ) -> Option<EscalatedGap<'a>> {
        let finding = repair.finding(cause)?;
        let (attempt_id, gap) = self.gap_for(repair.attempt_id, cause)?;
        Some(EscalatedGap {
            attempt_id,
            root_cause: &finding.root_cause,
            summary: &finding.summary,
            scope: finding.scope.as_deref(),
            evidence: &gap.evidence,
        })
    }

    fn gap_for(&self, attempt_id: Uuid, cause: &str) -> Option<(Uuid, &EngineGap)> {
        self.repairs().find_map(|owner| {
            let gap = owner.engine_gaps.get(cause)?;
            gap.retried_on
                .is_none_or(|previous| previous == attempt_id)
                .then_some((owner.attempt_id, gap))
        })
    }

    pub(super) fn retire_replayed_gap(&mut self, attempt_id: Uuid) {
        let Some(previous) = self
            .repair
            .as_ref()
            .filter(|repair| repair.attempt_id != attempt_id)
        else {
            return;
        };
        let prior_attempt = previous.attempt_id;
        let Some(cause) = previous.priority().map(str::to_owned) else {
            return;
        };
        if let Some((owner, _)) = self.gap_for(prior_attempt, &cause)
            && let Some(gap) = self
                .assignment_attempt_mut(owner)
                .and_then(|repair| repair.engine_gaps.get_mut(&cause))
            && gap.reported_during != attempt_id
        {
            gap.retried_on = Some(prior_attempt);
        }
    }

    pub(super) fn accepted_fix(&self, cause: &str) -> Option<AcceptedFix<'_>> {
        self.repairs().find_map(|owner| {
            let fix = owner.fix(cause)?;
            (!self.fix_was_integrated(&fix.commit)).then_some(AcceptedFix {
                attempt_id: owner.attempt_id,
                root_cause: &fix.root_cause,
                commit: &fix.commit,
            })
        })
    }

    fn fix_was_integrated(&self, commit: &str) -> bool {
        self.repairs().any(|repair| {
            repair
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.included_fixes.contains(commit))
        })
    }
}
