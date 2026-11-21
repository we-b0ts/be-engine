//! Application rule authorization and global field projection for shared read provenance.
use anyhow::Result;
use serde_json::Value;
use traffic_contract::time::ClockPair;

pub use traffic_contract::provenance::{TimeCopyLeaf, TimeCopyRecord};

#[derive(Clone, Debug, Default)]
pub struct SchemaCopyRules;

impl traffic_contract::provenance::CopyRuleScope for SchemaCopyRules {
    fn permits(rule: &str) -> bool {
        schema_rule(rule)
    }
}

#[allow(dead_code)]
pub type TimeCopyLookup = traffic_contract::provenance::TimeCopyLookup<SchemaCopyRules>;
pub type VerifiedTimeCopy = traffic_contract::provenance::VerifiedTimeCopy<SchemaCopyRules>;

#[derive(Default)]
pub struct TimeCopyStore(traffic_contract::provenance::TimeCopyStore<SchemaCopyRules>);

impl std::ops::Deref for TimeCopyStore {
    type Target = traffic_contract::provenance::TimeCopyStore<SchemaCopyRules>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for TimeCopyStore {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl TimeCopyStore {
    pub fn delivered_copies(&self, case: &str) -> DeliveredTimeCopies {
        DeliveredTimeCopies(self.0.delivered_copies(case))
    }
}

pub mod delivered;
pub use delivered::DeliveredTimeCopies;

pub fn schema_rule(id: &str) -> bool {
    id == crate::policy::GLOBAL_JSON_ID
        || id == "global.mysql"
        || id == "global.redis"
        || id == "builtin.time"
}

/// Source chooses each global format; retain the authored pointer pattern so
/// equal stored values can be copied through independently shaped carriers.
pub fn global_leaves(
    root: &Value,
    plan: &crate::policy::CompiledJsonPolicy,
    clocks: traffic_contract::compare::AnchorClocks,
) -> Result<Vec<TimeCopyLeaf>> {
    traffic_policy_execution::global::time_leaves(root, plan, clocks)
}
