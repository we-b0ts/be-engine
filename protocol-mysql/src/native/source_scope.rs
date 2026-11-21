//! Prove transaction lifetimes within one executable Source scope.
use std::collections::BTreeMap;

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use traffic_model::{attribution::DependencyScope, recording::ProtocolRef};
use traffic_protocol::connection::ReplaySessionStep;

use crate::{recorded::RecordedMysqlExchange, session_control, transaction_source};

pub(super) fn prepare(
    scope: DependencyScope,
    records: &[(usize, &Value)],
) -> Result<BTreeMap<usize, ReplaySessionStep>> {
    let mut exchanges = BTreeMap::new();
    for &(index, event) in records {
        if event["event_type"] != "mysql_exchange" {
            continue;
        }
        let mut record = RecordedMysqlExchange::deserialize(event)?;
        record.response.detach(());
        exchanges.insert(index, record);
    }
    let (controls, plans) = session_control::prepare_source_transactions(
        exchanges.iter().map(|(&index, record)| (index, record)),
        scope,
        &transaction_source::GlobalReads::default(),
    );
    let mut steps = BTreeMap::new();
    for (&index, record) in &exchanges {
        if controls.contains_key(&index) {
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
            if !controls.contains_key(&end.index) && exchanges[&end.index].response.status == "ok" {
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
            if read_only
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
            let mut first = if segment.strict || read_only || has_savepoint {
                0
            } else {
                segment.first_write.unwrap_or(0)
            };
            let begin = segment.members[0];
            let mode_only =
                controls.get(&begin) == Some(&session_control::SourceControl::BeginMode);
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
            steps.insert(members[0], ReplaySessionStep::Start);
            for (position, pair) in members.windows(2).enumerate() {
                let previous = &exchanges[&pair[0]];
                let after = ProtocolRef::connection(
                    "mysql",
                    previous.connection_id.expect("proven Source connection"),
                    previous.query_sequence.expect("proven Source sequence"),
                );
                steps.insert(
                    pair[1],
                    ReplaySessionStep::Continue {
                        after,
                        end: position + 2 == members.len(),
                    },
                );
            }
        }
    }
    steps.retain(|index, step| {
        let record = &exchanges[index];
        if *step != ReplaySessionStep::Unverified {
            return true;
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

fn in_transaction(status: Option<u16>) -> bool {
    status.is_some_and(|status| status & 0x2001 != 0)
}
