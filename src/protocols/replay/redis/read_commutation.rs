//! Explicit finite nil observations can commute with unrelated server data commands.
//! Source slots, responses, connection affinity and delivery consumption remain unchanged.
use super::*;
use crate::policy::{Database, NativeEffect, Protocol};

mod source;
pub(crate) use source::validate_source;
#[cfg(test)]
mod recorded_tests;
#[cfg(test)]
pub(super) mod tests;

const MAX_KEYS: usize = 128;
const MAX_READS: usize = 4096;

use traffic_protocol_redis::storage::ReadCommutationProof as Profile;

#[derive(Debug, Default)]
pub(super) struct ReadCommutation {
    prepared: BTreeSet<String>,
    profiles: Vec<Profile>,
}

impl ReadCommutation {
    pub(super) fn check_case_addition(
        &self,
        source: ReplaySource,
        case: Option<&str>,
    ) -> Result<()> {
        ensure!(
            source != ReplaySource::Case
                || !self.profiles.iter().any(|p| Some(p.case.as_str()) == case),
            "cannot extend a prepared read commutation Case inventory"
        );
        Ok(())
    }

    pub(super) fn check_inventory_addition(
        &self,
        record: &RecordedExchange,
        args: &[Vec<u8>],
        source: ReplaySource,
        case_id: Option<&str>,
    ) -> Result<()> {
        ensure!(
            !self.profiles.iter().any(|p| {
                record.native.database == p.database
                    && target_matches(
                        &p.target,
                        &record.native.target_host,
                        record.native.target_port,
                    )
                    && super::key_access::touches(&record.native.command, args, &p.key)
                    && !super::case_scope::is_other_ordinary_case(&p.case, source, case_id, record)
            }),
            "cannot add overlapping inventory after read commutation Source preparation"
        );
        Ok(())
    }
}

impl RedisReplayState {
    pub(super) fn prepare_read_commutation(&mut self, case: &str) -> Result<()> {
        if self.read_commutation.prepared.contains(case) {
            return Ok(());
        }
        let mut keys = BTreeSet::new();
        let mut profiles = Vec::new();
        for exchange in &self.exchanges {
            if exchange.source != ReplaySource::Case
                || exchange.case_id.as_deref() != Some(case)
                || exchange.record.native.command != "GET"
            {
                continue;
            }
            let target = TargetKey {
                host: exchange.record.native.target_host.clone(),
                port: exchange.record.native.target_port,
            };
            for rule in self
                .request_contracts
                .compiled_rules()
                .into_iter()
                .flat_map(|p| &p.native)
            {
                if !matches!(rule.rule.effect, NativeEffect::RedisReadCommutation(_))
                    || !self.request_contracts.native_rule_scope_matches(
                        &rule.rule.id,
                        Some(case),
                        Protocol::Redis,
                        &target,
                        Some(&Database::Index(exchange.record.native.database)),
                        exchange.record.native.username.as_deref(),
                    )
                    || !rule.rule.selector.key.as_ref().is_some_and(|selector| {
                        exchange.args.first().is_some_and(|key| {
                            crate::policy::runtime::native_projection::key(selector).matches(key)
                        })
                    })
                {
                    continue;
                }
                if !keys.insert((
                    target.clone(),
                    exchange.record.native.database,
                    exchange.args[0].clone(),
                )) {
                    continue;
                }
                ensure!(
                    profiles.len() < MAX_KEYS,
                    "read commutation exceeds Case key limit"
                );
                profiles.push(source::prepare(self, case, &rule.rule.id, exchange)?);
            }
        }
        ensure!(
            profiles.iter().map(|p| p.reads.len()).sum::<usize>() <= MAX_READS,
            "read commutation exceeds Case read limit"
        );
        // Install only after every selected key has a complete proof. A rejected
        // profile must not relax an earlier key or consume any finite exchange.
        for profile in profiles {
            for &index in &profile.reads {
                self.exchanges[index].read_commutation_rule = Some(profile.rule.clone());
            }
            self.read_commutation.profiles.push(profile);
        }
        self.read_commutation.prepared.insert(case.into());
        Ok(())
    }
}
