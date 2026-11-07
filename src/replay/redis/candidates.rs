//! Native Redis partitions do not include values that time/id rules may change.
use super::*;
use crate::replay::execution_plan::CaseMembership;
use crate::replay::{
    command_matching::CommandExchangeScope,
    native_index::{
        CandidateCursor, CandidateLookup, LaneIndex, LaneKey, LaneOwner, NativeKey, NativeQuery,
        ProtocolIndex, RedisKey, ScopePartition,
    },
};

#[derive(Debug)]
pub(in crate::replay) struct Candidates {
    count: usize,
    index: ProtocolIndex,
    lanes: LaneIndex,
    members: CaseMembership,
}

impl Default for Candidates {
    fn default() -> Self {
        Self {
            count: 0,
            index: ProtocolIndex::redis(),
            lanes: LaneIndex::default(),
            members: CaseMembership::default(),
        }
    }
}

impl Candidates {
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
                    host: normalize_host(&record.target_host),
                    port: record.target_port,
                },
                record.resp_version,
                record.database,
                record.username.as_deref(),
                &record.command,
            );
            self.index.register(NativeKey::Redis(key.clone()), index);
            if exchange.subscription_alias {
                key.scope = ScopePartition::Shared;
                self.index.register(NativeKey::Redis(key), index);
            }
            self.lanes.register(
                LaneKey {
                    owner: LaneOwner::new(exchange.source),
                    case: exchange.case_id.clone(),
                    connection: record.connection_id,
                },
                record.sequence,
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
        let scoped = self.index.lookup(NativeQuery::Redis(&key));
        if !source.is_run_owned() {
            return scoped;
        }
        key.scope = ScopePartition::Shared;
        scoped.merge(self.index.lookup(NativeQuery::Redis(&key)))
    }

    pub(super) fn lane_blocker(
        &self,
        exchanges: &[ReplayExchange],
        candidate: usize,
    ) -> Option<usize> {
        if !exchanges[candidate].preserves_connection_order() {
            return None;
        }
        self.lanes.blocker(candidate, |prior| {
            exchanges[prior].preserves_connection_order()
                && !exchanges[prior].satisfies_lane_order()
        })
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
