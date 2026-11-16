//! Application policy lifecycle and accounting over the shared value-service port.
use super::config::{LoadedReplayPolicy, load_replay_policy};
use super::report::ReplayPolicyReport;
use crate::replay::ReplayCase;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

// Historical witness readers retain these adapters during the evidence cutover.
pub(crate) mod mysql_native;
pub(super) mod mysql_values;
use crate::protocols::replay::mysql::{RecordedMysqlValue, ReplaySessionIdentity};
use crate::replay::TargetKey;
use chrono::{DateTime, Utc};

#[derive(Debug)]
pub(crate) struct ReplayPolicyRuntime {
    pub(crate) request_contracts: super::request_contract::RequestContracts,
    loaded: LoadedReplayPolicy,
}

impl ReplayPolicyRuntime {
    pub(crate) fn fingerprint(&self) -> &str {
        &self.loaded.fingerprint
    }

    #[cfg(test)]
    pub(crate) fn load(path: &Path, cases: &BTreeMap<String, ReplayCase>) -> Result<Self> {
        Self::load_with_sources(path, cases, true)
    }

    pub(crate) fn load_with_sources(
        path: &Path,
        cases: &BTreeMap<String, ReplayCase>,
        observe_sources: bool,
    ) -> Result<Self> {
        let loaded = load_replay_policy(path)?;
        for case in cases.values() {
            ensure!(
                case.dir.join("expected-response.json").is_file()
                    || case.dir.join("expected_response.json").is_file(),
                "replay policy requires an expected response under {}",
                case.dir.display()
            );
        }
        ensure!(
            loaded.document.dependency_rules.is_empty()
                && loaded.document.dynamic_values.is_empty(),
            "legacy dependency policies require an installed native state capability"
        );
        let mut request_contracts =
            super::request_contract::RequestContracts::load(&[], path, cases)?;
        request_contracts.configure_compiled(loaded.compiled.clone())?;
        if observe_sources && request_contracts.enabled() {
            for case in cases.values() {
                let bytes = crate::dependency_index::scoped::read_bytes(&case.dependencies_path)?;
                request_contracts.observe_source(&case.id, &bytes, None)?;
            }
        }
        Ok(Self {
            request_contracts,
            loaded,
        })
    }

    pub(crate) fn begin_case(&mut self, case: &str) {
        self.request_contracts.begin_case(case);
    }

    pub(crate) fn report(&self) -> ReplayPolicyReport {
        let dependency_rules = self.request_contracts.reports();
        let unused_applicable_dependency_rule_ids = dependency_rules
            .iter()
            .filter(|rule| rule.applicable && rule.matches == 0)
            .map(|rule| rule.id.clone())
            .collect();
        ReplayPolicyReport {
            version: self.loaded.document.version,
            path: self.loaded.path.display().to_string(),
            fingerprint: self.loaded.fingerprint.clone(),
            expected_response: self.loaded.document.expected_response,
            dependency_rules,
            global_formats: self.request_contracts.global_format_reports(),
            dynamic_bindings: Vec::new(),
            redis_read_backs: Vec::new(),
            key_bindings: Vec::new(),
            dynamic_capture_candidates: Vec::new(),
            request_contract_candidates: self.request_contracts.candidates(),
            unused_applicable_dependency_rule_ids,
            recorded_mysql_rule_applicability: BTreeMap::new(),
            recorded_redis_rule_applicability: BTreeMap::new(),
        }
    }
}
