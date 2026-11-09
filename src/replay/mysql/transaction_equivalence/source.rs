//! Prove complete Source transaction segments before assigning write obligations.
use super::*;
use crate::replay::dependencies::DependencyRecord;

mod error_rollback;
pub(super) mod locking_read;

pub(in crate::replay) struct Plan {
    pub setups: Vec<usize>,
    pub transactions: Vec<Segment>,
    pub reason: Option<&'static str>,
    pub dispatch_safe_before: Option<DateTime<Utc>>,
    pub failed_ends: Vec<RejectedEnd>,
}

#[derive(Debug)]
pub(in crate::replay) struct RejectedEnd {
    pub index: usize,
    pub reason: &'static str,
    pub end: &'static str,
    pub source_connection_id: Option<Uuid>,
    pub source_query_sequence: Option<u64>,
    pub failure_query_sequence: Option<u64>,
    pub missing_query_sequences: Vec<u64>,
    pub omitted_missing_query_sequences: u64,
}

struct Failure {
    reason: &'static str,
    sequence: Option<u64>,
    gap: Option<(u64, u64)>,
}

impl Failure {
    fn rejected_end(&self, index: usize, record: &RecordedMysqlExchange) -> Option<RejectedEnd> {
        let end = match normalize_sql(record.sql.as_deref()?).as_str() {
            "commit" => "commit",
            "rollback" => "rollback",
            _ => return None,
        };
        let count = self.gap.map_or(0, |(first, next)| next - first);
        Some(RejectedEnd {
            index,
            reason: self.reason,
            end,
            source_connection_id: record.connection_id,
            source_query_sequence: record.query_sequence,
            failure_query_sequence: self.sequence,
            missing_query_sequences: self
                .gap
                .map(|(first, next)| (first..next).take(8).collect())
                .unwrap_or_default(),
            omitted_missing_query_sequences: count.saturating_sub(8),
        })
    }
}

pub(in crate::replay) struct Segment {
    pub members: Vec<usize>,
    pub first_write: Option<usize>,
    pub write_count: usize,
    pub explicit: bool,
    pub strict: bool,
}

pub(super) fn prepare(
    records: &[DependencyRecord],
    optional: &BTreeMap<usize, OptionalSessionExchange>,
    scope: ReplaySource,
    global_reads: &source_evidence::GlobalReads,
) -> Vec<Plan> {
    let mut connections = BTreeMap::<Uuid, Vec<(usize, &RecordedMysqlExchange)>>::new();
    let mut plans = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if let DependencyRecord::MysqlExchange(record) = record {
            if super::super::is_nonsemantic_session_setup(record) {
                continue;
            }
            if let Some(connection) = record.connection_id {
                connections
                    .entry(connection)
                    .or_default()
                    .push((index, record));
            } else {
                let failed_end = Failure {
                    reason: "source_connection_missing",
                    sequence: record.query_sequence,
                    gap: None,
                }
                .rejected_end(index, record);
                let setups = (assignment(record).is_some() && !optional.contains_key(&index))
                    .then_some(index)
                    .into_iter()
                    .collect::<Vec<_>>();
                if setups.is_empty() && failed_end.is_none() {
                    continue;
                }
                plans.push(Plan {
                    setups,
                    transactions: Vec::new(),
                    reason: Some("source_connection_missing"),
                    dispatch_safe_before: None,
                    failed_ends: failed_end.into_iter().collect(),
                });
            }
        }
    }
    for mut records in connections.into_values() {
        let setups = records
            .iter()
            .filter(|(index, r)| assignment(r).is_some() && !optional.contains_key(index))
            .map(|(i, _)| *i)
            .collect();
        records.sort_by_key(|(_, record)| record.query_sequence);
        let mut transactions = Vec::new();
        let bridge_reads = (scope == ReplaySource::Case
            && !records
                .iter()
                .any(|(_, record)| global_reads.contains_wire(record)))
        .then_some(global_reads);
        let (reason, dispatch_safe_before, failed_ends) =
            collect_transactions(&records, &mut transactions, bridge_reads);
        plans.push(Plan {
            setups,
            transactions,
            reason,
            dispatch_safe_before,
            failed_ends,
        });
    }
    plans
}

fn assignment(record: &RecordedMysqlExchange) -> Option<bool> {
    matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        .then(|| {
            record
                .sql
                .as_deref()
                .and_then(crate::mysql::autocommit::assignment)
        })
        .flatten()
}

fn collect_transactions(
    records: &[(usize, &RecordedMysqlExchange)],
    complete: &mut Vec<Segment>,
    global_reads: Option<&source_evidence::GlobalReads>,
) -> (
    Option<&'static str>,
    Option<DateTime<Utc>>,
    Vec<RejectedEnd>,
) {
    // Duplicate wire identities can make an already collected end ambiguous.
    // Check them before retaining any partial connection proof.
    if records
        .windows(2)
        .any(|pair| pair[0].1.query_sequence == pair[1].1.query_sequence)
    {
        let failure = Failure {
            reason: "source_sequence_ambiguous",
            sequence: None,
            gap: None,
        };
        return (
            Some(failure.reason),
            None,
            records
                .iter()
                .filter_map(|(index, record)| failure.rejected_end(*index, record))
                .collect(),
        );
    }
    let mut active = Vec::<(usize, bool, bool)>::new();
    let mut explicit = false;
    let mut savepoints = crate::mysql::savepoint::Names::default();
    let mut previous: Option<(&RecordedMysqlExchange, u16)> = None;
    let mut reason = None;
    let mut dispatch_safe_before = None;
    let mut failed_ends = Vec::new();
    let mut failure: Option<Failure> = None;
    let mut recovered_end = None;
    for (position, &(index, record)) in records.iter().enumerate() {
        if recovered_end == Some(position) {
            // The strict error envelope already retained this real wire end.
            previous = Some((record, status_after(record).unwrap()));
            recovered_end = None;
            continue;
        }
        if let Some(failed) = &failure {
            // No permission is recovered until an independently known inactive
            // start. The incomplete earlier span remains strict and diagnosed.
            if record
                .server_status_before
                .is_none_or(|before| before & 0x2009 != 0)
            {
                failed_ends.extend(failed.rejected_end(index, record));
                continue;
            }
            failure = None;
        }
        let mut gap = None;
        let result: Result<(), &'static str> = (|| {
            let identity = identity_from_exchange(record).ok_or("source_identity_missing")?;
            let sequence = record.query_sequence.ok_or("source_sequence_missing")?;
            let before = record.server_status_before.ok_or("source_status_missing")?;
            let failed_update = update_outcome(record) == Some("error");
            let after = status_after(record)
                .or_else(|| {
                    let (_, next) = records.get(position + 1)?;
                    (failed_update
                        && next.query_sequence == sequence.checked_add(1)
                        && identity_from_exchange(next).as_ref() == Some(&identity))
                    .then_some(next.server_status_before)
                    .flatten()
                })
                .ok_or("source_status_missing")?;
            if let Some((previous, last_status)) = previous {
                if identity_from_exchange(previous).as_ref() != Some(&identity) {
                    return Err("source_identity_changed");
                }
                let last = previous.query_sequence.ok_or("source_sequence_missing")?;
                if last_status & 0x200b != before & 0x200b {
                    return Err("source_status_discontinuous");
                }
                if sequence <= last {
                    return Err("source_sequence_gap");
                }
                if last.checked_add(1) != Some(sequence) && before & 0x2009 != 0 {
                    let bridged = active.iter().all(|(_, write, strict)| !write && !strict)
                        && !active.is_empty()
                        && !explicit
                        && global_reads.is_some_and(|reads| {
                            record.connection_id.is_some_and(|connection| {
                                reads.bridges(
                                    connection,
                                    &identity,
                                    last,
                                    sequence,
                                    last_status,
                                    before,
                                )
                            })
                        });
                    if !bridged {
                        gap = last.checked_add(1).map(|first| (first, sequence));
                        return Err("source_sequence_gap");
                    }
                }
            } else if before & 0x2009 != 0 {
                return Err("source_transaction_start_unknown");
            }
            if let Some(enabled) = assignment(record) {
                if !optional_session::successful_control(record)
                    || before & 0x2009 != 0
                    || after & 0x200b != if enabled { 2 } else { 0 }
                    || !active.is_empty()
                {
                    return Err("source_autocommit_setup_unsafe");
                }
            } else if super::super::isolation::source_session_control(record) {
                // This does not grant an omission or a Target builtin response.
                // The isolation owner separately proves scope and restoration.
            } else if optional_session::successful_prepare(record)
                || optional_session::successful_ping(record)
            {
                // Neither command executes business SQL; both preserve continuity.
            } else if optional_session::successful_begin(record) {
                if !active.is_empty() {
                    return Err("source_transaction_restarted");
                }
                active.push((index, false, false));
                explicit = true;
            } else if optional_session::successful_end(record, &["commit", "rollback"]) {
                if active.is_empty() && before & 0x2009 != 0 {
                    return Err("source_transaction_start_unknown");
                }
                if !active.is_empty() {
                    let first_write = active.iter().position(|(_, write, _)| *write);
                    let write_count = active.iter().filter(|(_, write, _)| *write).count();
                    let strict = active.iter().any(|(_, _, strict)| *strict);
                    let mut members = active.drain(..).map(|(i, _, _)| i).collect::<Vec<_>>();
                    members.push(index);
                    complete.push(Segment {
                        members,
                        first_write,
                        write_count,
                        explicit,
                        strict,
                    });
                }
                explicit = false;
                savepoints.clear();
            } else if let Some(control) = record
                .sql
                .as_deref()
                .and_then(crate::mysql::savepoint::parse)
            {
                if !super::super::savepoints::complete(record)
                    || !savepoints.observe(&control)
                    || active.is_empty()
                {
                    return Err("source_savepoint_lifetime_unsupported");
                }
                active.push((index, false, false));
            } else {
                let (write, strict) =
                    statement(record).ok_or("source_statement_or_response_unsupported")?;
                if before & 0x200b == 2 && after & 0x200b == 2 && active.is_empty() {
                    // Source-native autocommit statements have no cross-statement obligation.
                } else {
                    if (!failed_update && after & 0x2009 != 1)
                        || (failed_update && after & 0x2008 != 0)
                        || before & 2 != after & 2
                        || (active.is_empty() && before & 0x2009 != 0)
                    {
                        return Err("source_transaction_status_unsupported");
                    }
                    active.push((index, write, strict));
                }
            }
            previous = Some((record, after));
            Ok(())
        })();
        if let Err(error) = result {
            if error == "source_status_missing"
                && let Some(segment) = error_rollback::prove(records, position, &active, explicit)
            {
                complete.push(segment);
                recovered_end = Some(position + 1);
                active.clear();
                savepoints.clear();
                explicit = false;
                previous = None;
                continue;
            }
            if reason.is_none() {
                reason = Some(error);
                if matches!(error, "source_status_discontinuous" | "source_sequence_gap") {
                    dispatch_safe_before = dispatch_cutoff(
                        records,
                        position,
                        previous,
                        active.first().map(|&(first, _, _)| first),
                    );
                }
            }
            let failed = Failure {
                reason: error,
                sequence: record.query_sequence,
                gap,
            };
            failed_ends.extend(failed.rejected_end(index, record));
            failure = Some(failed);
            active.clear();
            savepoints.clear();
            explicit = false;
            previous = None;
        }
    }
    if !active.is_empty() {
        reason.get_or_insert("source_transaction_unclosed");
    }
    (reason, dispatch_safe_before, failed_ends)
}

fn dispatch_cutoff(
    records: &[(usize, &RecordedMysqlExchange)],
    failure: usize,
    previous: Option<(&RecordedMysqlExchange, u16)>,
    open: Option<usize>,
) -> Option<DateTime<Utc>> {
    // An incomplete transaction cannot prove any part of its own lifetime.
    // An inactive prefix can use the preceding response as its boundary.
    let (cutoff, suffix) = if let Some(open) = open {
        let first = records[..failure]
            .iter()
            .rposition(|&(index, _)| index == open)?;
        (records[first].1.request_started_at?, &records[first..])
    } else {
        let (previous, status) = previous?;
        if status & 0x2009 != 0 {
            return None;
        }
        (previous.timestamp?, &records[failure..])
    };
    suffix
        .iter()
        .all(|(_, record)| {
            record
                .request_started_at
                .is_some_and(|started| started >= cutoff)
        })
        .then_some(cutoff)
}

fn status_after(record: &RecordedMysqlExchange) -> Option<u16> {
    if optional_session::successful_prepare(record) {
        record.server_status_before
    } else {
        record.response.server_status
    }
}

/// DML count is a request property; an UPDATE affecting zero rows is still a write.
fn statement(record: &RecordedMysqlExchange) -> Option<(bool, bool)> {
    let sql = record.sql.as_deref()?;
    if sql.len() > 1024 * 1024 {
        return None;
    }
    if update_outcome(record) == Some("error") {
        return Some((true, false));
    }
    if optional_session::complete_read(record)
        && optional_session::read::classify(sql) == optional_session::read::Effect::ReadOnly
    {
        return Some((false, false));
    }
    if !matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        || record.outcome != crate::DependencyExchangeOutcome::Response
        || !record.parse_warnings.is_empty()
        || !matches!(record.response.status.as_str(), "ok" | "resultset")
        || record.response.error_code.is_some()
        || record.response.error_message.is_some()
        || record.response.rows_truncated
    {
        return None;
    }
    if record.response.status == "resultset" && !optional_session::complete_read(record) {
        return None;
    }
    let tokens = crate::mysql::sql::tokens(sql);
    let write = tokens
        .as_ref()
        .and_then(|t| t.first())
        .is_some_and(|first| {
            ["insert", "update", "delete", "replace"]
                .iter()
                .any(|name| first.is(name))
        });
    let ordinary_write = write
        && record.response.status == "ok"
        && record.response.affected_rows.is_some()
        && record.response.no_rows()
        && record.response.columns.is_empty()
        && tokens
            .as_ref()
            .is_some_and(|t| !optional_session::read::has_session_effect(t))
        && optional_session::read::classify(sql) == optional_session::read::Effect::StateChange;
    // Unknown SQL and locking reads retain a complete same-socket transaction.
    Some((write, !ordinary_write))
}

/// A complete native transaction proves row-lock lifetime independently of the
/// driver's default autocommit mode. Unknown/session-persistent effects retain
/// the original Source setup even when their statement spans were delivered.
pub(super) fn requires_source_setup(record: &RecordedMysqlExchange) -> bool {
    if optional_session::successful_begin(record)
        || optional_session::successful_end(record, &["commit", "rollback"])
        || optional_session::successful_prepare(record)
        || optional_session::successful_ping(record)
    {
        return false;
    }
    match statement(record) {
        Some((_, false)) => false,
        Some((false, true)) if optional_session::complete_read(record) => record
            .sql
            .as_deref()
            .is_none_or(|sql| !locking_read::transaction_local(sql)),
        _ => true,
    }
}

/// Only ordinary UPDATE outcomes authorize the narrow no-effect rollback exception.
pub(super) fn update_outcome(record: &RecordedMysqlExchange) -> Option<&'static str> {
    let sql = record.sql.as_deref()?;
    if sql.len() > 1024 * 1024
        || !matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        || record.outcome != crate::DependencyExchangeOutcome::Response
        || !record.parse_warnings.is_empty()
        || record.response.rows_truncated
        || !record.response.no_rows()
        || !record.response.columns.is_empty()
    {
        return None;
    }
    let tokens = crate::mysql::sql::tokens(sql)?;
    if !tokens.first()?.is("update")
        || optional_session::read::has_session_effect(&tokens)
        || optional_session::read::classify(sql) != optional_session::read::Effect::StateChange
    {
        return None;
    }
    if record.response.status == "error" && record.response.error_code.is_some() {
        return Some("error");
    }
    if record.response.status != "ok"
        || record.response.error_code.is_some()
        || record.response.error_message.is_some()
    {
        return None;
    }
    Some(if record.response.affected_rows? == 0 {
        "zero_affected_rows"
    } else {
        "positive_affected_rows"
    })
}
