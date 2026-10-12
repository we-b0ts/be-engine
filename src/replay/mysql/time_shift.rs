//! Translate selected MySQL result cells on copies without changing recorded evidence.
use super::{RecordedMysqlResponse, ReplayBodyCapture, mysql_value_bytes};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::replay) fn parse_datetime(text: &str) -> Result<chrono::NaiveDateTime> {
    ensure!(
        text.split_once('.')
            .is_none_or(|(_, digits)| digits.len() <= 6),
        "MySQL time shift supports at most six fractional digits"
    );
    let value = chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f")
        .context("MySQL time shift requires a UTC MySQL datetime")?;
    ensure!(
        (1..=9999).contains(&chrono::Datelike::year(&value)),
        "invalid MySQL year"
    );
    Ok(value)
}

pub(in crate::replay) fn column_index(
    response: &RecordedMysqlResponse,
    name: &str,
) -> Result<usize> {
    let indexes: Vec<_> = response
        .columns
        .iter()
        .enumerate()
        .filter(|(_, column)| column.column.as_deref().unwrap_or(&column.name) == name)
        .map(|(index, _)| index)
        .collect();
    ensure!(
        indexes.len() == 1,
        "MySQL time shift column {name:?} is missing or ambiguous"
    );
    let index = indexes[0];
    ensure!(
        matches!(
            response.columns[index]
                .sql_type
                .to_ascii_lowercase()
                .as_str(),
            "datetime" | "timestamp"
        ),
        "MySQL time shift requires DATETIME or TIMESTAMP metadata"
    );
    Ok(index)
}

pub(in crate::replay) fn shift_response(
    response: &RecordedMysqlResponse,
    fields: &BTreeMap<String, BTreeSet<chrono::NaiveDateTime>>,
    times: crate::replay::assertion::RequestTimes,
) -> Result<RecordedMysqlResponse> {
    ensure!(
        response.status == "resultset" && !response.rows_truncated,
        "MySQL time shift requires a complete resultset"
    );
    let offset = times
        .target
        .context("MySQL time shift requires request_begin")?
        .signed_duration_since(
            times
                .source
                .context("MySQL time shift requires the recorded request timestamp")?,
        );
    let mut selected = Vec::new();
    for (name, preserved) in fields {
        let index = column_index(response, name)?;
        selected.push((index, preserved));
    }
    let mut output = response.clone();
    for row in &mut output.rows {
        ensure!(
            row.len() == response.columns.len(),
            "incomplete MySQL result row"
        );
        for (index, preserved) in &selected {
            let cell = &mut row[*index];
            if cell.kind == "null" {
                continue;
            }
            let bytes = mysql_value_bytes(cell)?;
            let text = std::str::from_utf8(&bytes)?;
            let time = parse_datetime(text)?;
            if preserved.contains(&time) {
                continue;
            }
            let shifted = time
                .checked_add_signed(offset)
                .context("MySQL time shift overflow")?;
            ensure!(
                (1..=9999).contains(&chrono::Datelike::year(&shifted)),
                "MySQL time shift exceeds the MySQL year range"
            );
            let precision = text.split_once('.').map_or(0, |(_, digits)| digits.len());
            let mut value = shifted.format("%Y-%m-%d %H:%M:%S").to_string();
            if precision > 0 {
                let fraction = format!("{:09}", chrono::Timelike::nanosecond(&shifted));
                value.push('.');
                value.push_str(&fraction[..precision]);
            }
            cell.value = Some(Value::String(value.clone()));
            if cell.raw.is_some() {
                cell.raw = Some(ReplayBodyCapture {
                    encoding: "utf8".into(),
                    data: value,
                });
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
