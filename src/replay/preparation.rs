//! Install one immutable Case view after all native registration has completed.
use super::*;
use execution_plan::{CaseExecutionPlan, NativeCaseRefs, SourceScopeIdentity};

impl ReplayState {
    pub(super) fn install_case_execution_plan(
        &mut self,
        case: &str,
        source: SourceScopeIdentity,
    ) -> Result<()> {
        let rules = self
            .replay_policy
            .as_ref()
            .map(|policy| policy.request_contracts.prepare_case_rules(case))
            .transpose()?
            .unwrap_or_default();
        self.http_candidates.register(&self.http_exchanges);
        self.mysql.prepare_candidates();
        self.redis.prepare_candidates();
        // Optional loop observations need their immutable Source proof even
        // when Target executes zero iterations and sends no Redis command.
        self.redis.prepare_optional_observations(case)?;
        let native = NativeCaseRefs {
            http: self.http_candidates.case_members(case),
            redis: self.redis.prepared_case_members(case),
            mysql: self.mysql.prepared_case_members(case),
        };
        let mut plan = CaseExecutionPlan::new(case.to_owned(), source, native);
        plan.rules = rules;
        self.case_execution_plans
            .insert(case.to_owned(), Arc::new(plan));
        Ok(())
    }

    pub(super) fn prepared_case(&self, case: &str) -> Result<&CaseExecutionPlan> {
        let plan = self
            .case_execution_plans
            .get(case)
            .context("Case dependency execution plan is not prepared")?;
        ensure!(
            plan.case_id == case,
            "Case execution plan has a foreign identity"
        );
        Ok(plan)
    }
}
