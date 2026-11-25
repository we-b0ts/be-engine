//! Attest an idle pool rollback immediately after a proven transaction end.
use std::collections::BTreeMap;

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::connection::{DriverPrelude, ReplaySessionStep};
use uuid::Uuid;

use crate::{recorded::RecordedMysqlExchange, session_control, session_identity};

const SERVER_STATUS_IN_TRANS: u16 = 1;
const SERVER_QUERY_NO_GOOD_INDEX_USED: u16 = 16;
const SERVER_QUERY_NO_INDEX_USED: u16 = 32;
const QUERY_INDEX_FLAGS: u16 = SERVER_QUERY_NO_GOOD_INDEX_USED | SERVER_QUERY_NO_INDEX_USED;

pub(super) fn prove(
    records: &[(usize, &Value)],
    steps: &BTreeMap<usize, ReplaySessionStep>,
) -> Result<BTreeMap<usize, DriverPrelude>> {
    let mut wire_order = BTreeMap::<(Uuid, u64), Option<(usize, &Value)>>::new();
    for &(position, event) in records {
        if event["event_type"] != "mysql_exchange" {
            continue;
        }
        let Some(connection) = event["connection_id"]
            .as_str()
            .and_then(|id| id.parse().ok())
        else {
            continue;
        };
        let Some(sequence) = event["query_sequence"].as_u64() else {
            continue;
        };
        wire_order
            .entry((connection, sequence))
            .and_modify(|entry| *entry = None)
            .or_insert(Some((position, event)));
    }

    let mut excluded = BTreeMap::new();
    for (&(connection, sequence), cleanup) in &wire_order {
        let Some((position, cleanup)) = *cleanup else {
            continue;
        };
        if cleanup["command"] != "COM_QUERY"
            || cleanup["server_status_before"] != 0
            || !cleanup["sql"].as_str().is_some_and(|sql| {
                let sql = sql.trim();
                sql.strip_suffix(';')
                    .unwrap_or(sql)
                    .trim_end()
                    .eq_ignore_ascii_case("rollback")
            })
        {
            continue;
        }
        let Some((end_position, end)) = sequence
            .checked_sub(1)
            .and_then(|prior| wire_order.get(&(connection, prior)).copied().flatten())
        else {
            continue;
        };
        if !matches!(
            steps.get(&end_position),
            Some(
                ReplaySessionStep::Continue { end: true, .. }
                    | ReplaySessionStep::ReadOnlyEnd { .. }
            )
        ) || end["capture_complete"] != true
            || cleanup["capture_complete"] != true
        {
            continue;
        }
        if idle_rollback_after(
            &RecordedMysqlExchange::deserialize(end)?,
            &RecordedMysqlExchange::deserialize(cleanup)?,
        ) {
            excluded.insert(position, DriverPrelude::MysqlPostTransactionIdleRollback);
        }
    }
    Ok(excluded)
}

fn idle_rollback_after(end: &RecordedMysqlExchange, cleanup: &RecordedMysqlExchange) -> bool {
    let identity = session_identity::identity_from_exchange(end);
    // The prior query's index diagnostics can still be set on entry to
    // COMMIT or ROLLBACK. They do not change the transaction state.
    end.server_status_before
        .is_some_and(|flags| flags & !QUERY_INDEX_FLAGS == SERVER_STATUS_IN_TRANS)
        && end.response.server_status == Some(0)
        && cleanup.server_status_before == Some(0)
        && cleanup.response.server_status == Some(0)
        && identity.is_some()
        && session_identity::identity_from_exchange(cleanup) == identity
        && session_control::successful_end(end, &["commit", "rollback"])
        && session_control::successful_end(cleanup, &["rollback"])
        && captured_clean_control(end)
        && captured_clean_control(cleanup)
        && end
            .capture
            .as_ref()
            .zip(cleanup.capture.as_ref())
            .is_some_and(|(end, cleanup)| {
                end.process_epoch == cleanup.process_epoch && end.sequence < cleanup.sequence
            })
}

fn captured_clean_control(record: &RecordedMysqlExchange) -> bool {
    !record.lifecycle_cleanup
        && record.params.is_none()
        && record.response.wire_prefix.is_empty()
        && record.capture.as_ref().is_some_and(|capture| {
            capture.semantic_required
                && capture.sequence > 0
                && capture.effect_index == 0
                && capture.transformations.is_empty()
                && record.connection_id.zip(record.query_sequence).is_some_and(
                    |(connection, sequence)| {
                        capture.protocol_ref
                            == ProtocolRef::connection("mysql", connection, sequence)
                    },
                )
        })
}
