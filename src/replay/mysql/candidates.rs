//! Ordered immutable scope indexes. Availability and all policy decisions stay live.
use super::*;
use crate::replay::execution_plan::CaseMembership;
use crate::replay::native_index::{
    CandidateLookup, LaneIndex, LaneKey, LaneOwner, MysqlCommand, MysqlKey, NativeKey, NativeQuery,
    ProtocolIndex, ScopePartition,
};
use std::sync::Arc;
use traffic_protocol_mysql::sql_family as family;
mod groups;
mod windows;
pub(super) use family::classify as sql_family;
pub(super) use family::select_hint;
use family::{Family, SelectHint};

#[derive(Debug)]
pub(super) struct Candidates {
    count: usize,
    index: ProtocolIndex,
    exempt: ProtocolIndex,
    members: CaseMembership,
    lanes: LaneIndex,
    families: Vec<Option<Family>>,
    selects: Vec<Option<SelectHint>>,
    savepoints: Vec<Option<crate::mysql::savepoint::Command>>,
    windows: windows::Windows,
    groups: groups::Groups,
}

impl Default for Candidates {
    fn default() -> Self {
        Self {
            count: 0,
            index: ProtocolIndex::mysql(),
            exempt: ProtocolIndex::mysql(),
            members: CaseMembership::default(),
            lanes: LaneIndex::default(),
            families: Vec::new(),
            selects: Vec::new(),
            savepoints: Vec::new(),
            windows: windows::Windows::default(),
            groups: groups::Groups::default(),
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
    pub(super) fn register_exempt(
        &mut self,
        exchanges: &[ReplayExchange],
        indices: impl Iterator<Item = usize>,
    ) {
        for index in indices {
            let exchange = &exchanges[index];
            let identity = ReplaySessionIdentity {
                target: Some(exchange.identity.target.clone()),
                database: exchange.identity.database.clone(),
                username: exchange.identity.username.clone(),
            };
            for command in [None, Some(exchange.record.command.as_str())] {
                if let Some(key) = key(
                    exchange.source,
                    exchange.case_id.as_deref(),
                    &identity,
                    command,
                ) {
                    self.exempt.register(NativeKey::Mysql(key), index);
                }
            }
        }
        self.exempt.seal();
    }

    pub(super) fn lookup_exempt(
        &self,
        source: ReplaySource,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: Option<&str>,
    ) -> Arc<[usize]> {
        let Some(key) = key(source, case, identity, command) else {
            return Arc::from([]);
        };
        self.exempt.lookup(NativeQuery::Mysql(&key)).into_indices()
    }
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
            self.selects.push(
                tokens
                    .as_deref()
                    .and_then(|tokens| SelectHint::from_tokens(tokens)),
            );
            self.groups
                .register(exchange, self.selects[index].is_some());
            self.savepoints.push(
                exchange
                    .record
                    .sql
                    .as_deref()
                    .and_then(crate::mysql::savepoint::parse),
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
                self.windows.register(
                    key.clone(),
                    self.selects[index].as_ref().map(|hint| hint.table.as_str()),
                    index,
                    exchange,
                );
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

    pub(super) fn permits_select(
        &self,
        candidate: usize,
        actual: Option<&SelectHint>,
        exact_shape: bool,
    ) -> bool {
        self.selects
            .get(candidate)
            .and_then(Option::as_ref)
            .zip(actual)
            .is_none_or(|(source, actual)| {
                source.table == actual.table
                    && (!exact_shape || source.scalar_shape == actual.scalar_shape)
            })
    }

    pub(super) fn blocked_candidates<'a>(
        &'a self,
        exchanges: &'a [ReplayExchange],
    ) -> impl FnMut(usize) -> bool + 'a {
        self.lanes.blocked_candidates(move |prior| {
            !exchanges[prior].status.is_consumed() && exchanges[prior].optional_session.is_none()
        })
    }

    pub(super) fn savepoint(&self, index: usize) -> Option<&crate::mysql::savepoint::Command> {
        self.savepoints[index].as_ref()
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
        self.lookup(source, case, identity, command)
    }

    pub(super) fn lookup(
        &self,
        source: ReplaySource,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: Option<&str>,
    ) -> Arc<[usize]> {
        let Some(key) = key(source, case, identity, command) else {
            return Arc::from([]);
        };
        self.index.lookup(NativeQuery::Mysql(&key)).into_indices()
    }

    pub(super) fn select_window(
        &self,
        case: &str,
        identity: &ReplaySessionIdentity,
        command: &str,
        table: Option<&str>,
        timeline: &crate::replay::control::input_timing::Live,
    ) -> Option<windows::Selection> {
        let key = key(ReplaySource::Case, Some(case), identity, Some(command))?;
        if let Some(table) = table
            && let Some(window) = self.windows.optimistic(
                &key,
                table,
                timeline.mysql_dispatch_prefix(case),
                |anchor| timeline.mysql_candidate_anchor(case, anchor),
            )
        {
            return Some(window);
        }
        self.windows.select(&key, table, |anchor| {
            timeline.mysql_candidate_cutoff(case, anchor)
        })
    }

    pub(super) fn select_hypothesis_window(
        &self,
        case: &str,
        identity: &ReplaySessionIdentity,
        command: &str,
        window: &windows::Selection,
    ) -> Option<Vec<usize>> {
        let key = key(ReplaySource::Case, Some(case), identity, Some(command))?;
        self.windows
            .select(&key, None, |_| Some(window.cutoff))
            .map(|selection| selection.indices)
    }

    pub(super) fn claimed(&mut self, index: usize) {
        self.windows.claimed(index);
    }

    pub(super) fn sql_group(&self, index: usize) -> Option<usize> {
        self.groups.get(index)
    }
}
