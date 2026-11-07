//! Reserve equivalent first reads without assigning a Source occurrence.
use super::*;
use crate::replay::admission::{ClaimKind, ClaimTicket, Lifecycle};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Default)]
pub(in crate::replay::mysql) struct Index {
    firsts: BTreeMap<usize, (usize, usize)>,
    seconds: BTreeMap<usize, usize>,
    groups: BTreeMap<usize, Group>,
    pending: BTreeMap<(usize, u64), Vec<ClaimTicket>>,
    lifecycle: Lifecycle,
    next: usize,
}

#[derive(Debug)]
struct Group {
    response: [u8; 32],
    members: Vec<(usize, usize)>,
    locking_count: usize,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::replay::mysql) struct Reservation {
    group: usize,
    window: u64,
}

#[derive(Hash, PartialEq, Eq)]
struct Key<'a> {
    case: &'a str,
    target: &'a TargetKey,
    database: Option<&'a str>,
    username: Option<&'a str>,
    sql: &'a str,
    before: u16,
    duration_ms: u64,
}

impl Index {
    pub(super) fn register(
        &mut self,
        plans: &[source::Plan],
        mapping: &BTreeMap<usize, usize>,
        exchanges: &[ReplayExchange],
    ) {
        let mut strict = HashMap::new();
        for segment in plans.iter().flat_map(|plan| &plan.transactions) {
            if segment.explicit || segment.write_count != 0 || !segment.strict {
                continue;
            }
            let [first, second, end] = segment.members.as_slice() else {
                continue;
            };
            let (Some(&first), Some(&second), Some(&end)) =
                (mapping.get(first), mapping.get(second), mapping.get(end))
            else {
                continue;
            };
            if !source::locking_read::transaction_local(
                exchanges[second].record.sql.as_deref().unwrap_or_default(),
            ) || normalize_sql(exchanges[end].record.sql.as_deref().unwrap_or_default())
                != "commit"
            {
                continue;
            }
            if let Some(key) = key(&exchanges[first])
                && same_case(&exchanges[second])
                && same_case(&exchanges[end])
                && let Some(response) = recorded_fingerprint(&exchanges[first])
            {
                strict
                    .entry(key)
                    .or_insert_with(HashMap::new)
                    .entry(response)
                    .or_insert_with(Vec::new)
                    .push((first, second));
            }
        }
        if strict.is_empty() {
            return;
        }
        let mut ordinary = HashMap::new();
        for segment in plans.iter().flat_map(|plan| &plan.transactions) {
            if segment.explicit
                || segment.strict
                || segment.write_count != 0
                || segment.members.len() < 3
                || segment
                    .members
                    .iter()
                    .any(|index| !mapping.contains_key(index))
            {
                continue;
            }
            let first = mapping[&segment.members[0]];
            let second = mapping[&segment.members[1]];
            if let Some(key) = key(&exchanges[first])
                && let Some(responses) = strict.get(&key)
                && same_case(&exchanges[second])
                && let Some(response) = recorded_fingerprint(&exchanges[first])
                && responses.contains_key(&response)
            {
                ordinary
                    .entry((key, response))
                    .or_insert_with(Vec::new)
                    .push((first, second));
            }
        }
        for ((key, response), mut ordinary) in ordinary {
            let locking = &strict[&key][&response];
            let group = locking[0].0;
            let locking_connection = exchanges[group].record.connection_id;
            if locking
                .iter()
                .any(|(first, _)| exchanges[*first].record.connection_id != locking_connection)
            {
                continue;
            }
            ordinary
                .retain(|(first, _)| exchanges[*first].record.connection_id != locking_connection);
            if ordinary.is_empty() {
                continue;
            }
            let mut members = locking.clone();
            members.extend(ordinary);
            for &(first, second) in &members {
                self.firsts.insert(first, (group, second));
                self.seconds.insert(second, first);
            }
            self.groups.insert(
                group,
                Group {
                    response,
                    members,
                    locking_count: locking.len(),
                },
            );
        }
    }

    pub(in crate::replay::mysql) fn is_first(&self, index: usize) -> bool {
        self.firsts.contains_key(&index)
    }

    pub(in crate::replay::mysql) fn reserve(
        &mut self,
        index: usize,
        response: &RecordedMysqlResponse,
        exchanges: &[ReplayExchange],
        window_for: impl Fn(&ReplayExchange, &ReplayExchange) -> Option<u64>,
        can_defer: bool,
    ) -> Result<Option<(Reservation, ClaimTicket)>, ()> {
        let Some(&(group, second)) = self.firsts.get(&index) else {
            return Ok(None);
        };
        let group_info = &self.groups[&group];
        let Some(window) = window_for(&exchanges[index], &exchanges[second]) else {
            return Ok(None);
        };
        let pending = self.pending.entry((group, window)).or_default();
        pending.retain(|ticket| ticket.satisfies(crate::replay::admission::Barrier::Admitted));
        if !can_defer {
            return if pending.is_empty() {
                Ok(None)
            } else {
                Err(())
            };
        }
        let is_available = |&(first, second): &(usize, usize)| {
            exchanges[first].status.is_available()
                && exchanges[second].status.is_available()
                && window_for(&exchanges[first], &exchanges[second]) == Some(window)
        };
        let (locking, ordinary) = group_info.members.split_at(group_info.locking_count);
        if pending.is_empty() {
            if !locking.iter().any(is_available) || !ordinary.iter().any(is_available) {
                return Ok(None);
            }
        } else if group_info
            .members
            .iter()
            .filter(|pair| is_available(pair))
            .nth(pending.len())
            .is_none()
        {
            return Err(());
        }
        if fingerprint(response) != Some(group_info.response) {
            return if pending.is_empty() {
                Ok(None)
            } else {
                Err(())
            };
        }
        let id = self.next;
        self.next += 1;
        let claim = self
            .lifecycle
            .claim(
                id,
                &mut ReplayExchangeStatus::Available,
                ClaimKind::Response,
            )
            .unwrap();
        pending.push(claim.observer());
        Ok(Some((Reservation { group, window }, claim)))
    }

    pub(in crate::replay::mysql) fn resolve(
        &self,
        reservation: Reservation,
        second: usize,
        exchanges: &[ReplayExchange],
        window_for: impl Fn(&ReplayExchange, &ReplayExchange) -> Option<u64>,
    ) -> Option<usize> {
        let &first = self.seconds.get(&second)?;
        (self.firsts[&first].0 == reservation.group
            && exchanges[first].status.is_available()
            && window_for(&exchanges[first], &exchanges[second]) == Some(reservation.window))
        .then_some(first)
    }

    pub(in crate::replay::mysql) fn confirm(
        &mut self,
        reservation: Reservation,
        ticket: &ClaimTicket,
    ) -> bool {
        let finished = self
            .lifecycle
            .complete(ticket, &mut ReplayExchangeStatus::Responding);
        if let Some(pending) = self
            .pending
            .get_mut(&(reservation.group, reservation.window))
        {
            pending.retain(|ticket| {
                ticket.satisfies(crate::replay::admission::Barrier::Admitted)
                    && !ticket.satisfies(crate::replay::admission::Barrier::Delivered)
            });
        }
        finished
    }

    pub(in crate::replay::mysql) fn fail(&mut self, ticket: &ClaimTicket) -> bool {
        self.lifecycle
            .fail(ticket, &mut ReplayExchangeStatus::Responding)
    }
}

pub(in crate::replay::mysql) fn window(
    timing: Option<&crate::replay::control::input_timing::Live>,
    first: &ReplayExchange,
    second: &ReplayExchange,
) -> Option<u64> {
    timing?.mysql_prefix_window(
        first.case_id.as_deref()?,
        first.record.request_started_at?,
        second.record.request_started_at?,
    )
}

fn key(exchange: &ReplayExchange) -> Option<Key<'_>> {
    let record = &exchange.record;
    let sql = record.sql.as_deref()?;
    if !same_case(exchange)
        || exchange.optional_session.is_some()
        || record.lifecycle_cleanup
        || record.command != "COM_QUERY"
        || record.outcome != crate::DependencyExchangeOutcome::Response
        || record
            .params
            .as_ref()
            .is_some_and(|params| !params.is_empty())
        || record.result_row_count().is_none_or(|rows| rows > 16)
        || record.response.columns.len() > 32
        || !record.response.wire_prefix.is_empty()
        || record.response.rows_truncated
        || record.server_status_before? & 0x200b != 0
        || record.response.server_status? & 0x200b != 1
        || optional_session::read::classify(sql) != optional_session::read::Effect::ReadOnly
    {
        return None;
    }
    Some(Key {
        case: exchange.case_id.as_deref()?,
        target: &exchange.identity.target,
        database: exchange.identity.database.as_deref(),
        username: exchange.identity.username.as_deref(),
        sql,
        before: record.server_status_before?,
        duration_ms: record.duration_ms,
    })
}

fn same_case(exchange: &ReplayExchange) -> bool {
    exchange.source == ReplaySource::Case
        && exchange.record.capture.as_ref().is_none_or(|capture| {
            matches!(capture.attribution, crate::DependencyOwner::Case { origin_case_id, .. }
                if exchange.case_id.as_deref().and_then(|case| Uuid::parse_str(case).ok()) == Some(origin_case_id))
        })
}

fn recorded_fingerprint(exchange: &ReplayExchange) -> Option<[u8; 32]> {
    let response = &exchange.record.response;
    if response
        .evidence
        .as_ref()
        .is_some_and(|evidence| evidence.location.length > MAX_RESPONSE_BYTES as u64)
    {
        return None;
    }
    fingerprint(&response.materialize().ok()?)
}

fn fingerprint(response: &RecordedMysqlResponse) -> Option<[u8; 32]> {
    let bytes = serde_json::to_vec(response).ok()?;
    (bytes.len() <= MAX_RESPONSE_BYTES).then(|| Sha256::digest(bytes).into())
}
