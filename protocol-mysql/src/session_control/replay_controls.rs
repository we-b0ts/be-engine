//! Source-side control verdicts shared by finite Replay and ownership admission.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use traffic_model::{DependencyExchangeOutcome, attribution::DependencyScope};

use super::{
    OptionalSessionExchange, OrderedConnection, ordered_connections, ordinary_read, read,
    successful_begin, successful_control, successful_end,
};
use crate::{
    isolation::{self, Level},
    recorded::RecordedMysqlExchange,
    session_identity::{DependencyIdentity, identity_from_exchange},
    transaction_source,
};

const ACTIVE_OR_AMBIGUOUS: u16 = 0x2009;
const TRANSACTION_STATUS: u16 = ACTIVE_OR_AMBIGUOUS | crate::types::SERVER_STATUS_AUTOCOMMIT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceControl {
    AutocommitMode,
    BeginMode,
    InactiveEnd,
    ReadOnlyEnd,
}

impl SourceControl {
    pub fn is_optional_end(self) -> bool {
        matches!(self, Self::InactiveEnd | Self::ReadOnlyEnd)
    }
}

/// Classify controls from native connection order, using the caller's stable
/// record positions. An active end needs its complete ordinary-read prefix.
/// Projected scopes can leave a connection gap, which cannot supply that prefix.
pub fn classify_source_controls<'a, E: 'a>(
    records: impl IntoIterator<Item = (usize, &'a RecordedMysqlExchange<E>)>,
) -> BTreeMap<usize, SourceControl> {
    observe_source_controls(records).optional
}

/// Prove control equivalence together with the Source transaction membership
/// that keeps writes and row locks inside a real Target transaction.
pub fn prepare_source_transactions<'a, E: 'a>(
    records: impl Iterator<Item = (usize, &'a RecordedMysqlExchange<E>)> + Clone,
    scope: DependencyScope,
    global_reads: &transaction_source::GlobalReads,
) -> (
    BTreeMap<usize, SourceControl>,
    Vec<transaction_source::Plan>,
) {
    let mut controls = observe_source_controls(records.clone());
    let setup = controls
        .optional
        .iter()
        .filter_map(|(&index, &control)| {
            (control == SourceControl::AutocommitMode)
                .then_some((index, OptionalSessionExchange::Autocommit))
        })
        .collect();
    let plans = transaction_source::prepare(records.clone(), &setup, scope, global_reads);
    if !controls.plain_begins.is_empty() {
        let indexed = records.collect::<BTreeMap<_, _>>();
        for segment in plans.iter().flat_map(|plan| &plan.transactions) {
            let Some(&begin) = segment.members.first().filter(|_| segment.explicit) else {
                continue;
            };
            if controls.plain_begins.contains(&begin)
                && segment
                    .members
                    .iter()
                    .all(|index| !transaction_source::requires_source_setup(indexed[index]))
            {
                controls.optional.insert(begin, SourceControl::BeginMode);
            }
        }
    }
    (controls.optional, plans)
}

#[derive(Default)]
struct Controls {
    optional: BTreeMap<usize, SourceControl>,
    plain_begins: BTreeSet<usize>,
}

fn observe_source_controls<'a, E: 'a>(
    records: impl IntoIterator<Item = (usize, &'a RecordedMysqlExchange<E>)>,
) -> Controls {
    let mut controls = Controls::default();
    let mut read_sql = HashMap::new();
    for exchanges in ordered_connections(records).into_values() {
        classify_connection(exchanges, &mut read_sql, &mut controls);
    }
    controls
}

struct Observation {
    sequence: u64,
    identity: Option<DependencyIdentity>,
    status: Option<u16>,
}

#[derive(Clone, Copy, Default)]
struct ReadSpan {
    active: bool,
    begin: Option<usize>,
}

fn classify_connection<'a, E>(
    exchanges: OrderedConnection<'a, E>,
    read_sql: &mut HashMap<&'a str, read::Effect>,
    controls: &mut Controls,
) {
    let mut previous: Option<Observation> = None;
    let mut read_span = ReadSpan::default();
    let mut snapshot_constraint = false;
    for (sequence, (index, record)) in exchanges {
        let identity = identity_from_exchange(record);
        let before = record.server_status_before.map(transaction_status);
        let adjacent = previous
            .as_ref()
            .filter(|last| last.sequence.checked_add(1) == Some(sequence));
        let continuous = adjacent.is_some_and(|last| {
            identity.is_some()
                && identity == last.identity
                && before.is_some()
                && before == last.status
        });
        if !continuous {
            read_span = ReadSpan::default();
        }
        snapshot_constraint |= record.sql.as_deref().is_some_and(changes_snapshot_contract);
        let inactive = before.is_some_and(|status| status & ACTIVE_OR_AMBIGUOUS == 0);
        let after = status_after(record);
        let eligible =
            identity.is_some() && !record.lifecycle_cleanup && (adjacent.is_none() || continuous);

        if eligible && successful_end(record, &["commit", "rollback"]) {
            if inactive {
                controls.optional.insert(index, SourceControl::InactiveEnd);
            } else if read_span.active {
                controls.optional.insert(index, SourceControl::ReadOnlyEnd);
                if let Some(begin) = read_span.begin {
                    controls.optional.insert(begin, SourceControl::BeginMode);
                }
            }
            read_span = ReadSpan::default();
        } else if eligible && inactive && disables_autocommit(record) {
            controls
                .optional
                .insert(index, SourceControl::AutocommitMode);
            read_span = ReadSpan::default();
        } else if eligible && !snapshot_constraint && successful_begin(record) {
            controls.plain_begins.insert(index);
            read_span = ReadSpan {
                active: true,
                begin: Some(index),
            };
        } else if eligible
            && !snapshot_constraint
            && after.is_some_and(|flags| flags & ACTIVE_OR_AMBIGUOUS == 1)
            && (read_span.active
                && (super::successful_prepare(record) || super::successful_ping(record))
                || (read_span.active || inactive) && ordinary_read(record, read_sql))
        {
            read_span.active = true;
        } else {
            read_span = ReadSpan::default();
        }

        previous = Some(Observation {
            sequence,
            identity,
            status: after,
        });
    }
}

fn transaction_status(flags: u16) -> u16 {
    flags & TRANSACTION_STATUS
}

fn status_after<E>(record: &RecordedMysqlExchange<E>) -> Option<u16> {
    if record.lifecycle_cleanup
        || record.outcome != DependencyExchangeOutcome::Response
        || !record.parse_warnings.is_empty()
        || record.response.error_code.is_some()
        || record.response.error_message.is_some()
    {
        return None;
    }
    super::status_after(record).map(transaction_status)
}

fn disables_autocommit<E>(record: &RecordedMysqlExchange<E>) -> bool {
    record
        .sql
        .as_deref()
        .and_then(crate::autocommit::assignment)
        == Some(false)
        && successful_control(record)
        && record.response.server_status.map(transaction_status) == Some(0)
}

/// Whether a session statement introduces an explicit snapshot constraint
/// that must be retained when comparing safe transaction cleanup.
pub fn changes_snapshot_contract(sql: &str) -> bool {
    let head = sql.trim_start();
    if !head
        .get(..3)
        .is_some_and(|word| word.eq_ignore_ascii_case("set"))
        && !head.starts_with(['/', '-', '#'])
    {
        return false;
    }
    if let Some((_, level)) = isolation::setting(sql) {
        return matches!(level, Level::RepeatableRead | Level::Serializable);
    }
    // Unrecognized transaction characteristics, including access mode and
    // session-variable spellings, cannot prove an ordinary implicit snapshot.
    crate::sql::tokens_shared(sql).is_none_or(|tokens| {
        tokens.first().is_some_and(|token| token.is("set"))
            && tokens.iter().any(|token| {
                [
                    "transaction",
                    "isolation",
                    "transaction_isolation",
                    "tx_isolation",
                    "transaction_read_only",
                    "tx_read_only",
                ]
                .iter()
                .any(|name| token.is(name))
            })
    })
}
