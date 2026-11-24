//! Prove transaction lifetimes within one executable Source scope.
use std::collections::BTreeMap;

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use traffic_model::{attribution::DependencyScope, recording::ProtocolRef};
use traffic_protocol::connection::{EventSessionPreparation, ReplaySessionStep};

use crate::{recorded::RecordedMysqlExchange, session_control, transaction_source};

mod driver_prelude;
mod idle_cleanup;

pub(super) fn prepare_event_session(
    records: &[(usize, &Value)],
) -> Result<EventSessionPreparation> {
    let mut driver_prelude = driver_prelude::prove(records)?;
    let mandatory = records
        .iter()
        .copied()
        .filter(|(position, _)| !driver_prelude.contains_key(position))
        .collect::<Vec<_>>();
    let mut steps = prepare(DependencyScope::Startup, &mandatory, true)?;
    let cleanup = idle_cleanup::prove(&mandatory, &steps)?;
    steps.retain(|position, _| !cleanup.contains_key(position));
    driver_prelude.extend(cleanup);
    Ok(EventSessionPreparation {
        steps,
        driver_prelude,
    })
}

pub(super) fn prepare(
    scope: DependencyScope,
    records: &[(usize, &Value)],
    event_session: bool,
) -> Result<BTreeMap<usize, ReplaySessionStep>> {
    let mut exchanges = BTreeMap::new();
    let mut snapshot_constraints = BTreeMap::new();
    for &(index, event) in records {
        if event["event_type"] != "mysql_exchange" {
            continue;
        }
        let mut record = RecordedMysqlExchange::deserialize(event)?;
        record.response.detach(());
        if event_session
            && record
                .sql
                .as_deref()
                .is_some_and(session_control::changes_snapshot_contract)
            && let Some(connection) = record.connection_id
        {
            let sequence = record.query_sequence.unwrap_or_default();
            snapshot_constraints
                .entry(connection)
                .and_modify(|first: &mut u64| *first = (*first).min(sequence))
                .or_insert(sequence);
        }
        exchanges.insert(index, record);
    }
    let (controls, plans) = session_control::prepare_source_transactions(
        exchanges.iter().map(|(&index, record)| (index, record)),
        scope,
        &transaction_source::GlobalReads::default(),
    );
    let mut steps = BTreeMap::new();
    for (&index, record) in &exchanges {
        if !event_session && controls.contains_key(&index) {
            steps.insert(index, ReplaySessionStep::Optional);
        } else if in_transaction(record.server_status_before)
            || in_transaction(record.response.server_status)
            || record.response.server_status.is_none()
                && record
                    .server_status_before
                    .is_some_and(|before| before & 2 == 0)
        {
            // Unclosed and cross-owner spans cannot authorize a write or end
            // using an unrelated Target transaction.
            steps.insert(index, ReplaySessionStep::Unverified);
        }
    }
    for plan in plans {
        for end in plan.failed_ends {
            if (event_session || !controls.contains_key(&end.index))
                && exchanges[&end.index].response.status == "ok"
            {
                steps.insert(end.index, ReplaySessionStep::Unverified);
            }
        }
        for segment in plan.transactions {
            let has_savepoint = segment.members.iter().any(|index| {
                exchanges[index]
                    .sql
                    .as_deref()
                    .and_then(crate::savepoint::parse)
                    .is_some()
            });
            let read_only = segment.write_count == 0 && !segment.strict && !has_savepoint;
            if !event_session
                && read_only
                && segment
                    .members
                    .last()
                    .is_some_and(|end| controls.contains_key(end))
            {
                for index in &segment.members {
                    if !controls.contains_key(index) {
                        steps.remove(index);
                    }
                }
                continue;
            }
            let mut first = if event_session || segment.strict || read_only || has_savepoint {
                0
            } else {
                segment.first_write.unwrap_or(0)
            };
            let begin = segment.members[0];
            let mode_only = !event_session
                && controls.get(&begin) == Some(&session_control::SourceControl::BeginMode);
            if mode_only {
                first = first.max(1);
            } else if session_control::successful_begin(&exchanges[&begin]) {
                // Explicit Source setup remains a required member when
                // the span's effects cannot be reduced to a mode change.
                first = 0;
            }
            for index in &segment.members[..first] {
                if !controls.contains_key(index) {
                    steps.remove(index);
                }
            }
            let members = &segment.members[first..];
            let first_record = &exchanges[&members[0]];
            let implicit_start = event_session
                && !segment.explicit
                && !has_savepoint
                && opens_implicit_read_transaction(first_record)
                && first_record.connection_id.is_some_and(|connection| {
                    snapshot_constraints
                        .get(&connection)
                        .is_none_or(|first_constraint| {
                            first_record
                                .query_sequence
                                .is_some_and(|sequence| sequence < *first_constraint)
                        })
                })
                && if segment.strict {
                    locked_read_and_rollback(&exchanges, members)
                } else {
                    first_record.sql.as_deref().is_some_and(|sql| {
                        session_control::read::classify(sql)
                            == session_control::read::Effect::ReadOnly
                    })
                };
            let start = if implicit_start {
                ReplaySessionStep::ImplicitStart
            } else {
                ReplaySessionStep::Start
            };
            steps.insert(members[0], start);
            for (position, pair) in members.windows(2).enumerate() {
                let previous = &exchanges[&pair[0]];
                let after = ProtocolRef::connection(
                    "mysql",
                    previous.connection_id.expect("proven Source connection"),
                    previous.query_sequence.expect("proven Source sequence"),
                );
                let end = position + 2 == members.len();
                let step = if event_session
                    && end
                    && read_only
                    && controls.get(&pair[1]) == Some(&session_control::SourceControl::ReadOnlyEnd)
                {
                    ReplaySessionStep::ReadOnlyEnd { after }
                } else {
                    ReplaySessionStep::Continue { after, end }
                };
                steps.insert(pair[1], step);
            }
        }
    }
    steps.retain(|index, step| {
        let record = &exchanges[index];
        if *step != ReplaySessionStep::Unverified {
            return true;
        }
        if event_session && missing_table_metadata_read(record) {
            return false;
        }
        if session_control::complete_read(record)
            && record.sql.as_deref().is_some_and(|sql| {
                session_control::read::classify(sql) == session_control::read::Effect::ReadOnly
            })
        {
            if record
                .server_status_before
                .is_some_and(|status| status & 0x2009 == 0)
            {
                // The ordinary read itself first opened an implicit Source
                // transaction. Ownership projection may leave its separately
                // proved optional terminal outside this executable partition.
                return false;
            }
            *step = ReplaySessionStep::InTransaction;
        }
        true
    });
    Ok(steps)
}

fn opens_implicit_read_transaction(record: &RecordedMysqlExchange) -> bool {
    !record.lifecycle_cleanup
        && record
            .server_status_before
            .is_some_and(|status| status & 0x200b == 0)
        && record
            .response
            .server_status
            .is_some_and(|status| status & 0x200b == 1)
        && session_control::complete_read(record)
}

fn locked_read_and_rollback(
    exchanges: &BTreeMap<usize, RecordedMysqlExchange>,
    members: &[usize],
) -> bool {
    let [read, end] = members else {
        return false;
    };
    let read = &exchanges[read];
    let end = &exchanges[end];
    // This grants only the explicit Target start. The recorded lock and rollback
    // remain paired by their physical Source sequence and actual delivery receipt.
    read.command == "COM_QUERY"
        && read.params.is_none()
        && !end.lifecycle_cleanup
        && end
            .server_status_before
            .is_some_and(|status| status & 0x200b == 1)
        && end
            .response
            .server_status
            .is_some_and(|status| status & 0x200b == 0)
        && session_control::successful_end(end, &["rollback"])
        && read.sql.as_deref().is_some_and(|sql| {
            crate::sql::bounds::statement_shared(sql).is_some_and(|tokens| {
                !tokens.iter().any(|token| token.is("("))
                    && tokens.last_chunk::<2>().is_some_and(|[for_token, update]| {
                        for_token.is("for") && update.is("update")
                    })
            }) && transaction_source::locking_read::transaction_local(sql)
        })
}

fn missing_table_metadata_read(record: &RecordedMysqlExchange) -> bool {
    let Some(sql) = record.sql.as_deref() else {
        return false;
    };
    if !sql
        .split_ascii_whitespace()
        .next()
        .is_some_and(|word| word.eq_ignore_ascii_case("describe"))
    {
        return false;
    }
    let Some(tokens) = crate::sql::tokens(sql) else {
        return false;
    };
    use crate::sql::Token;
    let identifier = |token: &Token| matches!(token, Token::Word(_) | Token::Identifier(_));
    let describe = match tokens.as_slice() {
        [_, table] => identifier(table),
        [_, schema, dot, table] => identifier(schema) && dot.is(".") && identifier(table),
        _ => false,
    };
    // MySQL error packets do not carry a post-status. An exact missing-table
    // response to a metadata-only read from an idle connection cannot start
    // a business transaction. Keep the request and its recorded error strict.
    describe
        && record.command == "COM_QUERY"
        && record.parse_warnings.is_empty()
        && !record.lifecycle_cleanup
        && record.params.as_ref().is_none_or(Vec::is_empty)
        && record.outcome == traffic_model::DependencyExchangeOutcome::Response
        && record
            .server_status_before
            .is_some_and(|status| status & 0x2009 == 0)
        && record.response.status == "error"
        && record.response.server_status.is_none()
        && matches!(record.response.error_code, Some(1049 | 1051 | 1146))
}

fn in_transaction(status: Option<u16>) -> bool {
    status.is_some_and(|status| status & 0x2001 != 0)
}
