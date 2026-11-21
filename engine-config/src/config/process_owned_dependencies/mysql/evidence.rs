//! Correlate bounded MySQL report summaries with complete immutable exchanges.
use super::MysqlBackgroundSelector;
use anyhow::{Context, Result, ensure};
use serde_json::Value;

pub fn identity_matches(selector: &MysqlBackgroundSelector, event: &Value) -> bool {
    event["target"]["host"]
        .as_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(&selector.target_host))
        && event["target"]["port"].as_u64() == Some(u64::from(selector.target_port))
        && event["database"].as_str() == Some(selector.database.as_str())
        && event["username"].as_str() == Some(selector.username.as_str())
}

pub fn query_matches(selector: &MysqlBackgroundSelector, event: &Value, sql: Option<&str>) -> bool {
    selector.matches_query(
        event["target"]["host"].as_str(),
        event["target"]["port"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok()),
        event["database"].as_str(),
        event["username"].as_str(),
        event["command"].as_str().unwrap_or_default(),
        sql,
    )
}

/// Reports retain only SQL fingerprints, so consume one corresponding record
/// per unused summary. Ambiguous incomplete duplicates cannot authorize a rule.
pub fn consume_unused(
    selector: &MysqlBackgroundSelector,
    unused: &Value,
    events: &mut Vec<Value>,
) -> Result<bool> {
    if !identity_matches(selector, unused) {
        return Ok(false);
    }
    let expected = unused["sql_summary"]["fingerprint"]
        .as_str()
        .context("unused MySQL exchange has no SQL fingerprint")?;
    let matches = |event: &Value| {
        event["event_type"] == "mysql_exchange"
            && event["command"] == unused["command"]
            && event["target_host"]
                .as_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(&selector.target_host))
            && event["target_port"].as_u64() == Some(u64::from(selector.target_port))
            && event["database"].as_str() == Some(selector.database.as_str())
            && event["username"].as_str() == Some(selector.username.as_str())
            && event["sql"]
                .as_str()
                .is_some_and(|sql| fingerprint(sql) == expected)
    };
    let pos = events
        .iter()
        .position(matches)
        .context("unused MySQL SQL fingerprint has no corresponding immutable dependency")?;
    if !query_matches(selector, unused, events[pos]["sql"].as_str()) {
        return Ok(false);
    }
    ensure!(
        unused["status"]
            .as_str()
            .is_none_or(|status| status == "resultset")
            && events
                .iter()
                .filter(|event| matches(event))
                .all(complete_response),
        "MySQL ownership evidence is truncated, failed or lacks complete row metadata"
    );
    events.remove(pos);
    Ok(true)
}

pub fn complete_response(event: &Value) -> bool {
    let response = &event["response"];
    let Some(columns) = response["columns"].as_array().filter(|c| !c.is_empty()) else {
        return false;
    };
    response["status"] == "resultset"
        && response["rows_truncated"] == false
        && event["parse_warnings"]
            .as_array()
            .is_some_and(Vec::is_empty)
        && response["rows"].as_array().is_some_and(|rows| {
            response["row_count"].as_u64() == Some(rows.len() as u64)
                && rows
                    .iter()
                    .all(|row| row.as_array().is_some_and(|row| row.len() == columns.len()))
        })
}

pub fn fingerprint(sql: &str) -> String {
    let hash = sql.bytes().fold(0xcbf29ce484222325_u64, |hash, b| {
        (hash ^ u64::from(b)).wrapping_mul(0x100000001b3)
    });
    format!("fnv1a64:{hash:016x}")
}
