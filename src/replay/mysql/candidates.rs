//! Ordered immutable scope indexes. Availability and all policy decisions stay live.
use super::*;
use crate::replay::execution_plan::CaseMembership;
use crate::replay::native_index::{
    CandidateLookup, LaneIndex, LaneKey, LaneOwner, MysqlCommand, MysqlKey, NativeKey, NativeQuery,
    ProtocolIndex, ScopePartition,
};
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct Candidates {
    count: usize,
    index: ProtocolIndex,
    members: CaseMembership,
    lanes: LaneIndex,
}

impl Default for Candidates {
    fn default() -> Self {
        Self {
            count: 0,
            index: ProtocolIndex::mysql(),
            members: CaseMembership::default(),
            lanes: LaneIndex::default(),
        }
    }
}

fn key(
    source: ReplaySource,
    case: Option<&str>,
    identity: &ReplaySessionIdentity,
    command: Option<&str>,
) -> Option<MysqlKey> {
    let target = identity.target.as_ref()?;
    Some(MysqlKey {
        scope: ScopePartition::new(source, case),
        host: target.host.clone(),
        port: target.port,
        database: normalize_identity_value(identity.database.as_deref()),
        username: normalize_identity_value(identity.username.as_deref()),
        command: MysqlCommand::new(command),
    })
}

impl Candidates {
    pub(super) fn register(&mut self, exchanges: &[ReplayExchange]) {
        // Some test/repair constructors append directly. Reconcile their immutable
        // inventory before lookup; payload release never changes vector positions.
        if self.count > exchanges.len() {
            *self = Self::default();
        }
        for (index, exchange) in exchanges.iter().enumerate().skip(self.count) {
            self.members
                .register(exchange.source, exchange.case_id.as_deref(), index);
            if let Some(connection) = exchange.record.connection_id {
                self.lanes.register_optional(
                    LaneKey {
                        owner: LaneOwner::new(exchange.source),
                        case: exchange.case_id.clone(),
                        connection,
                    },
                    exchange.record.query_sequence,
                    index,
                );
            }
            let identity = ReplaySessionIdentity {
                target: Some(exchange.identity.target.clone()),
                database: exchange.identity.database.clone(),
                username: exchange.identity.username.clone(),
            };
            if let Some(key) = key(
                exchange.source,
                exchange.case_id.as_deref(),
                &identity,
                None,
            ) {
                self.index.register(NativeKey::Mysql(key), index);
            }
            if let Some(key) = key(
                exchange.source,
                exchange.case_id.as_deref(),
                &identity,
                Some(&exchange.record.command),
            ) {
                self.index.register(NativeKey::Mysql(key), index);
            }
        }
        self.count = exchanges.len();
        self.index.seal();
        self.members.seal();
    }

    pub(super) fn case_members(&self, case: &str) -> Arc<[usize]> {
        self.members.for_case(case)
    }

    pub(super) fn lane_blocker(
        &self,
        exchanges: &[ReplayExchange],
        candidate: usize,
    ) -> Option<usize> {
        self.lanes.blocker(candidate, |prior| {
            !exchanges[prior].status.is_consumed() && exchanges[prior].optional_session.is_none()
        })
    }

    pub(super) fn select(
        &mut self,
        exchanges: &[ReplayExchange],
        source: ReplaySource,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: Option<&str>,
    ) -> Arc<[usize]> {
        // Direct test/repair appends keep their existing compatibility path.
        // Production registration can prepare each appended range before begin.
        self.register(exchanges);
        let Some(key) = key(source, case, identity, command) else {
            return Arc::from([]);
        };
        self.index.lookup(NativeQuery::Mysql(&key)).into_indices()
    }
}
