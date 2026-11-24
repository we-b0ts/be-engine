//! The complete SQLAlchemy/PyMySQL connection prelude is a driver recipe, not application I/O.
use std::collections::BTreeMap;

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::connection::DriverPrelude;
use uuid::Uuid;

use crate::{recorded::RecordedMysqlExchange, session_control, session_identity};

use super::missing_table_metadata_read;

const STARTUP_COMMANDS: [&str; 12] = [
    "set names",
    "set time_zone",
    "set autocommit = 0",
    "set names",
    "set session transaction isolation level read committed",
    "commit",
    "select version()",
    "select database()",
    "select @@transaction_isolation",
    "select @@sql_mode",
    "select @@lower_case_table_names",
    "rollback",
];

pub(super) fn prove(records: &[(usize, &Value)]) -> Result<BTreeMap<usize, DriverPrelude>> {
    let mut prefixes = BTreeMap::<Uuid, Vec<(u64, usize, &Value)>>::new();
    for &(position, event) in records {
        if event["event_type"] != "mysql_exchange" {
            continue;
        }
        let (Some(connection), Some(sequence)) = (
            event["connection_id"]
                .as_str()
                .and_then(|id| id.parse().ok()),
            event["query_sequence"].as_u64(),
        ) else {
            continue;
        };
        if sequence <= STARTUP_COMMANDS.len() as u64 + 2 {
            prefixes
                .entry(connection)
                .or_default()
                .push((sequence, position, event));
        }
    }
    let mut excluded = BTreeMap::new();
    for mut prefix in prefixes.into_values() {
        prefix.sort_unstable_by_key(|(sequence, _, _)| *sequence);
        let Some(prelude_and_probe) = prefix.get(..STARTUP_COMMANDS.len() + 1) else {
            continue;
        };
        if !valid(prelude_and_probe)? {
            continue;
        }
        for &(_, position, event) in &prefix[..STARTUP_COMMANDS.len()] {
            if event["capture"]["semantic_required"] == true {
                excluded.insert(position, DriverPrelude::MysqlSqlalchemyPymysql);
            }
        }
        if prefix.len() == STARTUP_COMMANDS.len() + 2
            && let Some(&(sequence, position, event)) = prefix.get(STARTUP_COMMANDS.len() + 1)
            && sequence == STARTUP_COMMANDS.len() as u64 + 2
            && idle_metadata_rollback(prelude_and_probe[STARTUP_COMMANDS.len()].2, event)?
        {
            excluded.insert(position, DriverPrelude::MysqlIdleMetadataRollback);
        }
    }
    Ok(excluded)
}

fn idle_metadata_rollback(probe: &Value, cleanup: &Value) -> Result<bool> {
    let probe = RecordedMysqlExchange::deserialize(probe)?;
    let cleanup = RecordedMysqlExchange::deserialize(cleanup)?;
    let identity = session_identity::identity_from_exchange(&probe);
    Ok(missing_table_metadata_read(&probe)
        && probe.server_status_before.map(transaction_flags) == Some(0)
        && identity.is_some()
        && session_identity::identity_from_exchange(&cleanup) == identity
        && cleanup.parse_warnings.is_empty()
        && matches_command(&cleanup, 11, "rollback", None))
}

fn valid(prefix: &[(u64, usize, &Value)]) -> Result<bool> {
    if prefix.len() != STARTUP_COMMANDS.len() + 1
        || prefix
            .iter()
            .zip(1..)
            .any(|((sequence, _, _), expected)| *sequence != expected)
    {
        return Ok(false);
    }
    let first_app: RecordedMysqlExchange =
        RecordedMysqlExchange::deserialize(prefix[STARTUP_COMMANDS.len()].2)?;
    let Some(identity) = session_identity::identity_from_exchange(&first_app) else {
        return Ok(false);
    };
    if first_app
        .capture
        .as_ref()
        .is_none_or(|metadata| !metadata.semantic_required)
        || first_app.server_status_before.map(transaction_flags) != Some(0)
    {
        return Ok(false);
    }
    for (index, ((_, _, event), expected)) in prefix.iter().zip(STARTUP_COMMANDS).enumerate() {
        let record = RecordedMysqlExchange::deserialize(*event)?;
        let expected_before = match index {
            0 if record.server_status_before.is_none() => None,
            0..=2 => Some(2),
            _ => Some(0),
        };
        if session_identity::identity_from_exchange(&record).as_ref() != Some(&identity)
            || !matches_command(&record, index, expected, expected_before)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn matches_command(
    record: &RecordedMysqlExchange,
    index: usize,
    expected: &str,
    expected_before: Option<u16>,
) -> bool {
    let Some(sql) = record.sql.as_deref() else {
        return false;
    };
    if ["/*", "--", "#"].iter().any(|marker| sql.contains(marker)) {
        return false;
    }
    let Some(capture) = &record.capture else {
        return false;
    };
    let Some(tokens) = crate::sql::tokens(sql) else {
        return false;
    };
    let expected_tokens = crate::sql::tokens(expected).expect("known driver statement tokenizes");
    let setup = matches!(index, 0 | 1 | 3);
    let syntax_matches = tokens.get(..expected_tokens.len()).is_some_and(|prefix| {
        prefix
            .iter()
            .zip(&expected_tokens)
            .all(|(actual, expected)| match (actual, expected) {
                (crate::sql::Token::Word(actual), crate::sql::Token::Word(expected)) => {
                    actual.eq_ignore_ascii_case(expected)
                }
                (actual, expected) => actual == expected,
            })
    }) && if setup {
        crate::session_setup::is_mysql_session_setup_sql(sql)
    } else {
        tokens.len() == expected_tokens.len()
    };
    let flags_match = record.server_status_before.map(transaction_flags) == expected_before
        && record.response.server_status.map(transaction_flags)
            == Some(if index < 2 { 2 } else { 0 });
    let result_matches = if (6..=10).contains(&index) {
        session_control::complete_read(record)
            && record.response.rows.len() == 1
            && record.response.columns.len() == 1
    } else {
        session_control::successful_control(record)
    };
    syntax_matches
        && flags_match
        && result_matches
        && !record.lifecycle_cleanup
        && record.command == "COM_QUERY"
        && record.params.as_ref().is_none_or(Vec::is_empty)
        && record.response.wire_prefix.is_empty()
        && capture.effect_index == 0
        && capture.transformations.is_empty()
        && capture.semantic_required != setup
        && record
            .connection_id
            .zip(record.query_sequence)
            .is_some_and(|(connection, sequence)| {
                capture.protocol_ref == ProtocolRef::connection("mysql", connection, sequence)
            })
}

fn transaction_flags(status: u16) -> u16 {
    // Autocommit, active/read-only transaction and more-results state.
    status & 0x200b
}
