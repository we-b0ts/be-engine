//! Read-only native SQL envelope and materialized scalar selection.
use anyhow::Result;
use serde_json::{Value, json};
use traffic_protocol::evidence::{
    MessageSide, ValueEvidence, ValueObservation, ValueQuery, ValueReader,
};

pub(super) fn query(
    event: &Value,
    payload: &[u8],
    query: ValueQuery<'_>,
    reader: &dyn ValueReader,
) -> Result<ValueEvidence> {
    let prefix = match query.side {
        MessageSide::Request => "/sql_values/",
        MessageSide::Response => "/request/sql_values/",
    };
    let materialized = query.pointer.starts_with(prefix);
    let observation = if query.value_index != 0 {
        ValueObservation::unavailable("selected document is unavailable")
    } else if materialized {
        select_cell(event, payload, query, prefix, reader)?
    } else {
        reader.select(payload, query.pointer)
    };
    let annotations = serde_json::from_value(json!({"sql_value_selection": {
        "request_pointer":"/sql_values/<sql-token-index>/value",
        "response_request_pointer":"/request/sql_values/<sql-token-index>/value",
        "decoded_json_pointer":"/sql_values/<sql-token-index>/json/<json-pointer>",
        "physical_field_pointer":"/sql_values/<sql-token-index>/field",
        "position_source":"physical_fields.fields[].observed_positions in unified-rule-candidates uses the same SQL token indexes",
        "semantics":"Each statement is materialized independently. Numbers retain exact normalized SQL text; strings preserve decoded native bytes. A field origin or decoded JSON view grants no matching permission and does not prove the two selected cells correspond."
    }}))?;
    Ok(ValueEvidence {
        observation,
        document_count: 1,
        representation: if materialized {
            "materialized_mysql_sql_value"
        } else {
            "native_witness_json"
        },
        annotations,
    })
}

fn select_cell(
    event: &Value,
    payload: &[u8],
    query: ValueQuery<'_>,
    prefix: &str,
    reader: &dyn ValueReader,
) -> Result<ValueObservation> {
    let Some((index, tail)) = query
        .pointer
        .strip_prefix(prefix)
        .and_then(|value| value.split_once('/'))
    else {
        return Ok(ValueObservation::unavailable(
            "SQL selection requires /sql_values/<token-index>/<cell-pointer>; response requests use /request/sql_values/...",
        ));
    };
    let Ok(index) = index.parse::<usize>() else {
        return Ok(ValueObservation::unavailable(
            "SQL token index must be a nonnegative integer",
        ));
    };
    Ok(
        match crate::witness::sql_value(payload, query.side, event["database"].as_str(), index) {
            Ok(Some(value)) => reader.select(&serde_json::to_vec(&value)?, &format!("/{tail}")),
            Ok(None) => ValueObservation::Missing,
            Err(error) => ValueObservation::unavailable(error.to_string()),
        },
    )
}
