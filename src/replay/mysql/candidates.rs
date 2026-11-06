//! Ordered immutable scope indexes. Availability and all policy decisions stay live.
use super::*;
use crate::replay::execution_plan::CaseMembership;
use crate::replay::native_index::{
    CandidateLookup, LaneIndex, LaneKey, LaneOwner, MysqlCommand, MysqlKey, NativeKey, NativeQuery,
    ProtocolIndex, ScopePartition,
};
use std::sync::Arc;
mod family;
use family::Family;
pub(super) use family::classify as sql_family;
pub(super) use family::sql_table;

#[derive(Debug)]
pub(super) struct Candidates {
    count: usize,
    index: ProtocolIndex,
    members: CaseMembership,
    lanes: LaneIndex,
    families: Vec<Option<Family>>,
    select_tables: Vec<Option<String>>,
}

impl Default for Candidates {
    fn default() -> Self {
        Self {
            count: 0,
            index: ProtocolIndex::mysql(),
            members: CaseMembership::default(),
            lanes: LaneIndex::default(),
            families: Vec::new(),
            select_tables: Vec::new(),
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
            let tokens = exchange
                .record
                .sql
                .as_deref()
                .and_then(family::bounded_tokens);
            self.families.push(
                tokens
                    .as_deref()
                    .and_then(|tokens| family::classify_tokens(tokens)),
            );
            self.select_tables.push(
                tokens
                    .as_deref()
                    .and_then(|tokens| family::select_table(tokens))
                    .map(str::to_owned),
            );
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

    pub(super) fn permits_sql(&self, candidate: usize, actual: Option<Family>) -> bool {
        self.families
            .get(candidate)
            .copied()
            .flatten()
            .zip(actual)
            .is_none_or(|(source, actual)| source == actual)
    }

    pub(super) fn permits_table(&self, candidate: usize, actual: Option<&str>) -> bool {
        self.select_tables
            .get(candidate)
            .and_then(|table| table.as_deref())
            .zip(actual)
            .is_none_or(|(source, actual)| source == actual)
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
