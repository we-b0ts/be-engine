//! Native Redis partitions do not include values that time/id rules may change.
use super::*;
use crate::replay::execution_plan::CaseMembership;
use crate::replay::{
    command_matching::CommandExchangeScope,
    native_index::{
        CandidateCursor, CandidateIndex, LaneIndex, LaneKey, LaneOwner, ScopePartition,
    },
};

type RedisKey = traffic_protocol_redis::candidate::Key<ScopePartition>;

#[derive(Debug, Default)]
pub(crate) struct Candidates {
    count: usize,
    index: CandidateIndex<RedisKey>,
    exempt: CandidateIndex<RedisKey>,
    lanes: LaneIndex,
    members: CaseMembership,
}

impl Candidates {
    pub(super) fn register_exempt(
        &mut self,
        exchanges: &[ReplayExchange],
        indices: impl Iterator<Item = usize>,
    ) {
        for index in indices {
            let exchange = &exchanges[index];
            let record = &exchange.record;
            let mut key = key(
                exchange.source,
                exchange.case_id.as_deref(),
                &TargetKey {
                    host: normalize_host(&record.native.target_host),
                    port: record.native.target_port,
                },
                record.native.resp_version,
                record.native.database,
                record.native.username.as_deref(),
                &record.native.command,
            );
            self.exempt.register(key.clone(), index);
            if exchange.subscription_alias {
                key.scope = ScopePartition::Shared;
                self.exempt.register(key, index);
            }
        }
        self.exempt.seal();
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn select_exempt(
        &self,
        source: ReplaySource,
        case: Option<&str>,
        target: &TargetKey,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
    ) -> CandidateCursor {
        let mut key = key(
            source,
            case,
            target,
            resp_version,
            database,
            username,
            command,
        );
        let scoped = self.exempt.lookup(&key);
        if !source.is_run_owned() {
            return scoped;
        }
        key.scope = ScopePartition::Shared;
        scoped.merge(self.exempt.lookup(&key))
    }
    pub(super) fn register(&mut self, exchanges: &[ReplayExchange]) {
        if self.count > exchanges.len() {
            *self = Self::default();
        }
        for (index, exchange) in exchanges.iter().enumerate().skip(self.count) {
            self.members
                .register(exchange.source, exchange.case_id.as_deref(), index);
            let record = &exchange.record;
            let mut key = key(
                exchange.source,
                exchange.case_id.as_deref(),
                &TargetKey {
                    host: normalize_host(&record.native.target_host),
                    port: record.native.target_port,
                },
                record.native.resp_version,
                record.native.database,
                record.native.username.as_deref(),
                &record.native.command,
            );
            self.index.register(key.clone(), index);
            if exchange.subscription_alias {
                key.scope = ScopePartition::Shared;
                self.index.register(key, index);
            }
            self.lanes.register(
                LaneKey {
                    owner: LaneOwner::new(exchange.source),
                    case: exchange.case_id.clone(),
                    connection: record.native.connection_id,
                },
                record.native.sequence,
                index,
            );
        }
        self.count = exchanges.len();
        self.index.seal();
        self.members.seal();
    }

    pub(super) fn case_members(&self, case: &str) -> Arc<[usize]> {
        self.members.for_case(case)
    }

    pub(super) fn case_lane_slot(
        &self,
        case: &str,
        connection: Uuid,
        sequence: u64,
    ) -> Option<usize> {
        self.lanes.unique_slot(
            &LaneKey {
                owner: LaneOwner::Case,
                case: Some(case.to_owned()),
                connection,
            },
            sequence,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn select(
        &self,
        source: ReplaySource,
        case: Option<&str>,
        target: &TargetKey,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
    ) -> CandidateCursor {
        let mut key = key(
            source,
            case,
            target,
            resp_version,
            database,
            username,
            command,
        );
        let scoped = self.index.lookup(&key);
        if !source.is_run_owned() {
            return scoped;
        }
        key.scope = ScopePartition::Shared;
        scoped.merge(self.index.lookup(&key))
    }

    pub(super) fn lane_blocker(
        &self,
        exchanges: &[ReplayExchange],
        candidate: usize,
    ) -> Option<usize> {
        self.lane_blocker_excluding(exchanges, candidate, |_| false)
    }

    pub(super) fn lane_blocker_excluding(
        &self,
        exchanges: &[ReplayExchange],
        candidate: usize,
        mut excluded: impl FnMut(usize) -> bool,
    ) -> Option<usize> {
        if !exchanges[candidate].preserves_connection_order() {
            return None;
        }
        self.lanes.blocker(candidate, |prior| {
            !excluded(prior)
                && exchanges[prior].preserves_connection_order()
                && !exchanges[prior].satisfies_lane_order()
        })
    }

    pub(super) fn lane_prefix(
        &self,
        first: usize,
        candidate: usize,
        limit: usize,
    ) -> Option<Vec<usize>> {
        self.lanes.bounded_prefix(first, candidate, limit)
    }

    pub(super) fn previous_lane_slot(&self, index: usize) -> Option<usize> {
        self.lanes.previous_slot(index)
    }
}

#[allow(clippy::too_many_arguments)]
fn key(
    source: ReplaySource,
    case: Option<&str>,
    target: &TargetKey,
    resp_version: u8,
    database: i64,
    username: Option<&str>,
    command: &str,
) -> RedisKey {
    RedisKey {
        scope: ScopePartition::new(source, case),
        host: target.host.clone(),
        port: target.port,
        resp_version,
        database,
        username: normalize_optional(username),
        command: command.to_ascii_uppercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redis_provider_keeps_cross_command_barriers_live_after_claim_and_failure() {
        let mut state = RedisReplayState::default();
        let lane = Uuid::new_v4();
        let mut targets = BTreeMap::new();
        for (sequence, command) in [(1, "GET"), (2, "DEL")] {
            let record = serde_json::from_value(json!({
                "connection_id":lane, "sequence":sequence, "target_host":"redis.test", "target_port":6379,
                "resp_version":2, "database":0,"username":null,"command":command,
                "args":[{"encoding":"utf8","data":"session"}],"response_kind":if command == "GET" {"bulk_string"} else {"integer"},
                "response":{"encoding":"utf8","data":if command == "GET" {"$1\r\nx\r\n"} else {":1\r\n"}},"replay_safe":true
            })).unwrap();
            state
                .register_exchange(
                    record,
                    ReplaySource::Case,
                    Some("active"),
                    &mut targets,
                    &[],
                )
                .unwrap();
        }
        let mut index = Candidates::default();
        index.register(&state.exchanges);
        let target = TargetKey {
            host: "redis.test".into(),
            port: 6379,
        };
        assert_eq!(
            index
                .select(
                    ReplaySource::Case,
                    Some("active"),
                    &target,
                    2,
                    0,
                    None,
                    "DEL"
                )
                .collect::<Vec<_>>(),
            [1]
        );
        assert_eq!(index.lane_blocker(&state.exchanges, 1), Some(0));
        state.exchanges[0].status = ReplayExchangeStatus::Responding;
        assert_eq!(index.lane_blocker(&state.exchanges, 1), None);
        assert!(!state.exchanges[0].status.is_consumed());
        state.exchanges[0].status = ReplayExchangeStatus::Failed;
        assert_eq!(index.lane_blocker(&state.exchanges, 1), Some(0));
        assert_eq!(index.case_members("active").as_ref(), [0, 1]);
        assert!(
            index
                .select(
                    ReplaySource::Case,
                    Some("other"),
                    &target,
                    2,
                    0,
                    None,
                    "DEL"
                )
                .next()
                .is_none()
        );
    }
}
