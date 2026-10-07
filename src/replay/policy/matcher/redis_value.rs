//! Project validated Redis rules and commit only selected-exchange usage.
use super::*;
use crate::replay::redis::value::ValueRule;
impl ReplayPolicyRuntime {
    pub(in crate::replay) fn redis_publish_rules(
        &self,
    ) -> Vec<crate::replay::redis::publish::PublishRule> {
        self.loaded
            .document
            .dependency_rules
            .iter()
            .filter_map(|rule| {
                let super::super::redis_value::RedisSelector::Publish(publish) =
                    rule.redis.as_ref()?
                else {
                    return None;
                };
                Some(crate::replay::redis::publish::PublishRule {
                    id: rule.id.clone(),
                    selector: crate::replay::redis::publish::RedisPublishSelector {
                        host: rule.target.host.clone().unwrap_or_default(),
                        port: rule.target.port.unwrap_or_default(),
                        channel: publish.publish.channel.clone(),
                        uuid_index: publish.publish.uuid_index,
                        uuid_field: publish.publish.uuid_field.clone(),
                    },
                })
            })
            .collect()
    }
    pub(in crate::replay) fn redis_lock_token_rules(
        &self,
    ) -> Vec<crate::replay::redis::lock::LockTokenRule> {
        self.loaded
            .document
            .dependency_rules
            .iter()
            .filter_map(|rule| {
                let super::super::redis_value::RedisSelector::Lock(lock) = rule.redis.as_ref()?
                else {
                    return None;
                };
                Some(crate::replay::redis::lock::LockTokenRule {
                    id: rule.id.clone(),
                    selector: crate::replay::redis::lock::RedisLockSelector {
                        host: rule.target.host.clone().unwrap_or_default(),
                        port: rule.target.port.unwrap_or_default(),
                        key: lock.lock.key.clone(),
                    },
                })
            })
            .collect()
    }

    pub(in crate::replay) fn redis_time_shift_rules(
        &self,
    ) -> Vec<(
        String,
        crate::replay::redis::time_shift::RedisTimeShiftSelector,
    )> {
        self.loaded
            .document
            .dependency_rules
            .iter()
            .filter_map(|rule| {
                let super::super::redis_value::RedisSelector::TimeShift(read) =
                    rule.redis.as_ref()?
                else {
                    return None;
                };
                Some((
                    rule.id.clone(),
                    crate::replay::redis::time_shift::RedisTimeShiftSelector {
                        host: rule.target.host.clone().unwrap_or_default(),
                        port: rule.target.port.unwrap_or_default(),
                        read: read.clone(),
                    },
                ))
            })
            .collect()
    }
    pub(in crate::replay) fn redis_value_rules(&self) -> Vec<ValueRule> {
        self.loaded
            .document
            .dependency_rules
            .iter()
            .flat_map(|rule| {
                rule.redis
                    .as_ref()
                    .map(|redis| redis.selectors(rule))
                    .unwrap_or_default()
                    .into_iter()
                    .map(|selector| ValueRule {
                        id: rule.id.clone(),
                        selector,
                    })
            })
            .collect()
    }
    pub(in crate::replay) fn commit_redis_value(&mut self, case_id: Option<&str>, ids: &[String]) {
        let mut decision = DependencyRuleDecision::default();
        for id in ids {
            decision.usage.entry(id.clone()).or_default().validations += 1;
        }
        self.commit(case_id, decision);
    }
}
