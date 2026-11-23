//! Install one immutable Case view after provider registration has completed.
use super::*;
use execution_plan::{CaseExecutionPlan, NativeCaseRefs, SourceScopeIdentity};

impl<P: ReplayProtocolSet> RuntimeState<P> {
    pub(super) fn prepare_native_candidates(&mut self) {
        self.native.core.seal();
        self.protocols.prepare_candidates();
    }

    pub(super) fn install_case_execution_plan(
        &mut self,
        case: &str,
        source: SourceScopeIdentity,
    ) -> Result<()> {
        let contracts = self.replay_policy.as_ref().map(|policy| policy.contracts());
        let rules = contracts
            .map(|contracts| contracts.prepare_case_rules(case))
            .transpose()?
            .unwrap_or_default();
        let native = NativeCaseRefs {
            registered: self.native.core.case_members(case),
            protocols: self.protocols.prepare_case(
                case,
                self.sequence_catalog.is_some(),
                contracts,
            )?,
        };
        let mut plan = CaseExecutionPlan::new(case.to_owned(), source, native);
        if let Some(catalog) = &self.sequence_catalog {
            let protocols = plan
                .native
                .protocols
                .values()
                .flat_map(|inventory| inventory.sequence.iter().map(|(_, sequence)| *sequence));
            let registered = plan
                .native
                .registered
                .iter()
                .filter_map(|index| self.native.recorded_sequence(*index));
            plan.sequence = Some(catalog.scope(protocols.chain(registered))?);
        }
        self.timers.validate_case(case, plan.sequence.as_deref())?;
        plan.rules = rules;
        self.native.finish_storage_preparation(case);
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
