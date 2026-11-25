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
    #[serde(with = "uuid::serde::simple")]
    attempt_id: Uuid,
    base_commit: Option<&'a str>,
    finding: &'a Finding,
}

impl Repair {
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

    fn is_assigned(&self, cause: &str) -> bool {
        self.plan
            .implementers
            .iter()
            .any(|finding| finding.root_cause == cause)
    }

    fn is_active(&self, cause: &str) -> bool {
        self.fix(cause).is_none() && !self.engine_gaps.contains_key(cause)
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
        let mut active = self
            .assignments()
            .filter(|(owner, finding)| owner.is_active(&finding.root_cause))
            .map(|(_, finding)| finding.root_cause.as_str())
            .collect::<BTreeSet<_>>();
        findings.sort_by_key(|finding| {
            Some(finding.root_cause.as_str()) != repair.first_unmatched.as_deref()
        });
        for finding in &findings {
            let cause = finding.root_cause.as_str();
            if repair.is_assigned(cause) {
                plan.implementers.push(finding.clone());
            } else if active.len() >= repair.max_implementers
                || active.contains(cause)
                || self.accepted_fix(cause).is_some()
                || self.gap_for(repair.attempt_id, cause).is_some()
            {
                plan.waiting.push(finding.clone());
            } else {
                active.insert(cause);
                plan.implementers.push(finding.clone());
            }
        }
        plan
    }

    pub(super) fn current_assignments(&self, first_unmatched: &str) -> Vec<Assignment<'_>> {
        let mut assignments: Vec<_> = self
            .assignments()
            .filter(|(owner, finding)| owner.is_active(&finding.root_cause))
            .map(|(owner, finding)| Assignment {
                attempt_id: owner.attempt_id,
                base_commit: owner.base_commit.as_deref(),
                finding,
            })
            .collect();
        assignments.sort_by_key(|assignment| assignment.finding.root_cause != first_unmatched);
        assignments
    }

    fn repairs(&self) -> impl Iterator<Item = &Repair> {
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
        let Some(cause) = previous.first_unmatched.clone() else {
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
            let integrated = self.repairs().any(|repair| {
                repair
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.included_fixes.contains(&fix.commit))
            });
            (!integrated).then_some(AcceptedFix {
                attempt_id: owner.attempt_id,
                root_cause: &fix.root_cause,
                commit: &fix.commit,
            })
        })
    }
}
