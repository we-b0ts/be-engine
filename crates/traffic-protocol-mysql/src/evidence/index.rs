//! Compact result metadata belongs to the native MySQL evidence owner.
use anyhow::Result;
use serde_json::{Value, json};
use traffic_protocol::evidence::index::IndexProjection;

pub(super) fn project(event: &Value) -> Result<IndexProjection> {
    let mut projection = IndexProjection::record(event.clone());
    if event["event_type"] == "mysql_exchange" {
        let columns = event["response"]["columns"].as_array().map_or(0, Vec::len);
        anyhow::ensure!(
            event["response"]["status"] != "resultset"
                || event["response"]["rows"]
                    .as_array()
                    .is_none_or(Vec::is_empty)
                || event["response"]["columns"].is_array(),
            "MySQL result rows have no column metadata"
        );
        let shape = event["response"]["rows"].as_array().map(|rows| {
            (
                rows.len(),
                rows.iter()
                    .all(|row| row.as_array().is_some_and(|row| row.len() == columns)),
            )
        });
        projection.metadata = json!({"row_shape":shape});
        if let Some(rows) = projection.record.pointer_mut("/response/rows") {
            *rows = Value::Array(Vec::new());
        }
    }
    Ok(projection)
}

pub(super) fn lookup(event: &Value) -> Result<IndexProjection> {
    let mut projection = IndexProjection::record(Value::Null);
    if let Some(endpoint) = crate::index::endpoint(event) {
        projection.endpoints.push(endpoint);
    }
    if event["event_type"] == "mysql_connection" {
        projection.observations.push(event.clone());
    }
    if let Some(summary) = crate::index::summary(event) {
        projection
            .lookups
            .push(traffic_protocol::evidence::index::LookupProjection {
                index: "mysql".into(),
                key: None,
                connection: event["connection_id"].as_str().map(ToOwned::to_owned),
                summary,
            });
    }
    Ok(projection)
}

pub(super) fn proof(event: &Value) -> Value {
    traffic_protocol::evidence::index::select_without(
        event,
        &["response", "raw"],
        &["sql", "params"],
    )
}
pub(super) fn complete(event: &Value) -> bool {
    event["replay_safe"] != false
        && event["response"]["status"] != "incomplete"
        && event["response"]["rows_truncated"] != true
}
