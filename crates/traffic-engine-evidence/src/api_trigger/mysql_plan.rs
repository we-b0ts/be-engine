//! API-origin SELECT/UPDATE selectors share the existing immutable plan/apply transaction.
use crate::config::{ApiTriggerSource, BackgroundDependencyRuleConfig, MysqlBackgroundSelector};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTriggeredMysqlSelector {
    #[serde(
        default,
        skip_serializing_if = "crate::config::api_trigger::mysql::disabled"
    )]
    pub include_transaction_boundaries: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_members: Vec<MysqlBackgroundSelector>,
    pub selector: MysqlBackgroundSelector,
    pub trigger_source: ApiTriggerSource,
    /// Zero-based '?' value in the SQL template, bound to the one capture.
    pub identity_value_index: usize,
}

impl ApiTriggeredMysqlSelector {
    pub fn rule(&self, name: &str, revision: &str, proof: &str) -> BackgroundDependencyRuleConfig {
        BackgroundDependencyRuleConfig::Mysql {
            include_transaction_boundaries: self.include_transaction_boundaries,
            transaction_members: self.transaction_members.clone(),
            name: name.into(),
            selector: self.selector.clone(),
            trigger_source: Some(self.trigger_source.clone()),
            identity_value_index: Some(self.identity_value_index),
            source_revision: revision.into(),
            source_evidence: proof.into(),
        }
    }
}

pub fn plan_api_triggered_mysql(
    rules_path: &Path,
    replay_path: &Path,
    source: &Path,
    name: &str,
    revision: &str,
    proof: &str,
    selector: &ApiTriggeredMysqlSelector,
) -> anyhow::Result<super::plan::ApiTriggeredMysqlPlan> {
    super::plan::plan(
        rules_path,
        replay_path,
        source,
        selector.rule(name, revision, proof),
    )
}
