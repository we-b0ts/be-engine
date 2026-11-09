//! Empty MySQL controls can complete the wire sequence of a proved tail.
use super::*;
use crate::dependency::observation::ProtocolRef;

pub(super) fn is_bounded_control(
    source: &SourceSnapshot,
    id: Uuid,
    victim: Uuid,
    anchors_share_origin: impl FnOnce(&Uuid, &Uuid) -> bool,
) -> Result<bool> {
    let capture = &source.exchanges[&id].capture;
    let ProtocolRef::Mysql {
        connection_id,
        sequence,
    } = capture.protocol_ref
    else {
        return Ok(false);
    };
    let same_victim = |id: &Uuid| {
        source.exchanges.get(id).is_some_and(|event| {
            event.complete
                && event.capture.semantic_required
                && event.capture.phase == CapturePhase::Runtime
                && event.capture.process_epoch == capture.process_epoch
                && matches!(event.capture.attribution, DependencyOwner::Case {origin_case_id, ..}
                    if origin_case_id == victim)
        })
    };
    if !same_victim(&id) {
        return Ok(false);
    }
    let adjacent = |sequence| {
        let ids = source
            .native
            .get(&("mysql".into(), connection_id.to_string(), sequence))?;
        let neighbour = *ids.first()?;
        (ids.len() == 1 && same_victim(&neighbour)).then_some(neighbour)
    };
    if adjacent(sequence) != Some(id) {
        return Ok(false);
    }
    let Some((before, after)) = sequence
        .checked_sub(1)
        .and_then(adjacent)
        .zip(sequence.checked_add(1).and_then(adjacent))
    else {
        return Ok(false);
    };
    if !anchors_share_origin(&before, &after) {
        return Ok(false);
    }
    let mut reader = crate::dependency_index::RecordReader::new(64 * 1024);
    Ok(empty_transaction_end(
        &source.original_selector(&id, &mut reader)?,
    ))
}

fn empty_transaction_end(record: &Value) -> bool {
    let empty = |value: &Value| value.as_array().is_some_and(Vec::is_empty);
    let response = &record["response"];
    record["event_type"] == "mysql_exchange"
        && record["command"] == "COM_QUERY"
        && record["sql"].as_str().is_some_and(|sql| {
            let sql = sql.trim();
            sql.eq_ignore_ascii_case("COMMIT") || sql.eq_ignore_ascii_case("ROLLBACK")
        })
        && record["outcome"] == "response"
        && empty(&record["parse_warnings"])
        && (record["params"].is_null() || empty(&record["params"]))
        && record["server_status_before"] == 0
        && response["server_status"] == 0
        && response["status"] == "ok"
        && response["affected_rows"] == 0
        && response["last_insert_id"] == 0
        && response["row_count"] == 0
        && response["rows_truncated"] == false
        && response["error_code"].is_null()
        && response["error_message"].is_null()
        && (response["wire_prefix"].is_null() || empty(&response["wire_prefix"]))
        && empty(&response["columns"])
        && empty(&response["rows"])
}
