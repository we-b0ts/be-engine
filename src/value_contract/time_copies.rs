//! Application rule authorization and global field projection for shared read provenance.
use super::time::ClockPair;
use anyhow::{Result, ensure};
use serde_json::Value;

use traffic_contract::provenance::MAX_CASE_COPIES;
pub(crate) use traffic_contract::provenance::{PhysicalOrigin, TimeCopyLeaf, TimeCopyRecord};

#[derive(Clone, Debug, Default)]
pub(crate) struct SchemaCopyRules;

impl traffic_contract::provenance::CopyRuleScope for SchemaCopyRules {
    fn permits(rule: &str) -> bool {
        schema_rule(rule)
    }
}

pub(crate) type TimeCopyLookup = traffic_contract::provenance::TimeCopyLookup<SchemaCopyRules>;
pub(crate) type VerifiedTimeCopy = traffic_contract::provenance::VerifiedTimeCopy<SchemaCopyRules>;

#[derive(Default)]
pub(crate) struct TimeCopyStore(traffic_contract::provenance::TimeCopyStore<SchemaCopyRules>);

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
    pub(crate) fn delivered_copies(&self, case: &str) -> DeliveredTimeCopies {
        DeliveredTimeCopies(self.0.delivered_copies(case))
    }
}

mod delivered;
pub(crate) use delivered::DeliveredTimeCopies;

pub(crate) fn schema_rule(id: &str) -> bool {
    id == crate::policy::GLOBAL_JSON_ID
        || id == "global.mysql"
        || id == "global.redis"
        || id == super::time::automatic::RULE_ID
}

/// Source chooses each global format; retain the authored pointer pattern so
/// equal stored values can be copied through independently shaped carriers.
pub(crate) fn global_leaves(
    root: &Value,
    plan: &crate::policy::CompiledJsonPolicy,
    clocks: super::json::AnchorClocks,
) -> Result<Vec<TimeCopyLeaf>> {
    let mut output = Vec::new();
    for selected in plan.selected_fields_with_clocks(root, clocks)? {
        let pointer = selected.pointer;
        let Some(value) = root.pointer(&pointer) else {
            continue;
        };
        let Some(time) = selected.contract.time() else {
            continue;
        };
        super::json::parse_time_pair(value, value, &time)?;
        output.push(TimeCopyLeaf {
            rule_id: selected.rule_id,
            pattern: selected.pattern,
            pointer,
            value: value.clone(),
            time,
        });
        ensure!(
            output.len() <= MAX_CASE_COPIES,
            "global time copy leaf enumeration exceeds its bound"
        );
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
