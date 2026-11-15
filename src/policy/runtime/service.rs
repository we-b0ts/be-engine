//! Bind the compiled application policy to Replay's shared lifecycle services.
use std::{collections::BTreeMap, path::Path};

use anyhow::Result;

use super::ReplayPolicyRuntime;
use crate::replay::ReplayCase;
use crate::replay::policy::PolicyReport;
use crate::replay::policy::ReplayPolicy;

impl ReplayPolicy for ReplayPolicyRuntime {
    type Contracts = super::request_contract::RequestContracts;

    fn load(path: &Path, cases: &BTreeMap<String, ReplayCase>, observe: bool) -> Result<Self> {
        Self::load_with_sources(path, cases, observe)
    }

    fn contracts(&self) -> &Self::Contracts {
        &self.request_contracts
    }
    fn contracts_mut(&mut self) -> &mut Self::Contracts {
        &mut self.request_contracts
    }
    fn fingerprint(&self) -> &str {
        Self::fingerprint(self)
    }

    fn report(&self) -> PolicyReport {
        let report = Self::report(self);
        let mut details = serde_json::to_value(&report)
            .expect("policy report serializes")
            .as_object()
            .expect("policy report is an object")
            .clone();
        details.remove("fingerprint");
        details.remove("unused_applicable_dependency_rule_ids");
        PolicyReport {
            fingerprint: report.fingerprint,
            unused_applicable_dependency_rule_ids: report.unused_applicable_dependency_rule_ids,
            details: details.into_iter().collect(),
        }
    }

    fn begin_case(&mut self, case: &str) {
        Self::begin_case(self, case);
    }

    fn observe_source(
        &mut self,
        case: &str,
        raw: &[u8],
        index: Option<&crate::dependency_index::FileIndex>,
    ) -> Result<()> {
        self.request_contracts.observe_source(case, raw, index)?;
        if self.dynamic_values.enabled() {
            self.dynamic_values.observe_source(case, raw)?;
        }
        Ok(())
    }

    fn async_rules(&self) -> crate::recorder::async_api::CompletionPolicy {
        self.request_contracts
            .compiled_rules()
            .map(|policy| policy.async_api.clone().into())
            .unwrap_or_default()
    }
}
