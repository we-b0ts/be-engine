//! Complete immutable key lifetimes prove metadata-only read/refresh equivalence.
use super::*;

impl RedisReplayState {
    pub(in crate::protocols::replay::redis) fn prepare_activity_case(
        &mut self,
        case: &str,
    ) -> Result<()> {
        if self.activity_refresh.prepared.contains(case) {
            return Ok(());
        }
        let mut profiles = Vec::new();
        let mut seen = BTreeSet::new();
        for seed in self.exchanges.iter().filter(|e| {
            e.source == ReplaySource::Case
                && e.case_id.as_deref() == Some(case)
                && e.record.native.command == "SET"
        }) {
            let target = TargetKey {
                host: seed.record.native.target_host.clone(),
                port: seed.record.native.target_port,
            };
            for compiled in self
                .request_contracts
                .compiled_rules()
                .into_iter()
                .flat_map(|p| &p.native)
            {
                let NativeEffect::RedisActivityRefresh(effect) = &compiled.rule.effect else {
                    continue;
                };
                let rule = &compiled.rule;
                if !self.request_contracts.native_rule_scope_matches(
                    &rule.id,
                    Some(case),
                    Protocol::Redis,
                    &target,
                    Some(&Database::Index(seed.record.native.database)),
                    seed.record.native.username.as_deref(),
                ) || !rule.selector.key.as_ref().is_some_and(|s| {
                    seed.args.first().is_some_and(|k| {
                        crate::policy::runtime::native_projection::key(s).matches(k)
                    })
                }) {
                    continue;
                }
                if !seen.insert((
                    target.clone(),
                    seed.record.native.database,
                    normalize_optional(seed.record.native.username.as_deref()),
                    seed.args[0].clone(),
                )) {
                    continue;
                }
                if let Some(proof) = traffic_protocol_redis::storage::activity::prepare(
                    &self.exchanges,
                    &self.connection_scopes,
                    case,
                    &rule.id,
                    &value::SourceValues {
                        state: self,
                        pointers: &effect.fields,
                    },
                    seed,
                )? {
                    profiles.push(Profile {
                        source: proof,
                        current: None,
                        failed: false,
                    });
                }
                ensure!(
                    profiles.len() <= MAX_KEYS,
                    "activity refresh exceeds Case key limit"
                );
            }
        }
        ensure!(
            profiles
                .iter()
                .flat_map(|p| &p.lifetimes)
                .filter(|l| l.eligible())
                .map(|l| l.reads.len() + l.writes.len())
                .sum::<usize>()
                <= MAX_CALLS,
            "activity refresh exceeds Source observation bound"
        );
        ensure!(
            profiles
                .iter()
                .flat_map(|p| &p.lifetimes)
                .flat_map(|l| l.reads.iter().chain(&l.writes))
                .all(|&index| self.exchanges[index].observation_rule.is_none()
                    && self.exchanges[index].read_commutation_rule.is_none()),
            "activity refresh overlaps another observation owner"
        );
        // Install no partial permission if any complete Source proof fails.
        for profile in profiles {
            for index in profile
                .lifetimes
                .iter()
                .filter(|l| l.eligible())
                .flat_map(|l| l.reads.iter().chain(&l.writes))
            {
                let e = &mut self.exchanges[*index];
                e.observation_rule = Some(profile.rule.clone());
                self.activity_refresh
                    .owned
                    .entry(case.into())
                    .or_default()
                    .insert((e.record.native.connection_id, e.record.native.sequence));
            }
            self.activity_refresh.profiles.push(profile);
        }
        self.activity_refresh.prepared.insert(case.into());
        Ok(())
    }
}
