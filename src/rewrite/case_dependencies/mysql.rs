//! Bounded MySQL query, identity and response facts for API-implementer diagnosis.
use super::*;

// Keep complete SQL for every template the MySQL ownership planner accepts.
const MAX_SQL_BYTES: usize = 8192;

#[derive(Default)]
pub(super) struct OperationBuilder {
    count: usize,
    outcomes: BTreeMap<String, usize>,
    response_statuses: BTreeMap<String, usize>,
    seen: BTreeSet<String>,
    representatives: Vec<RewriteMysqlExchangeDetail>,
}

impl OperationBuilder {
    pub(super) fn record(&mut self, event: &Value) -> Result<()> {
        self.count += 1;
        let outcome = identifier(event, "outcome")?;
        increment_optional(&mut self.outcomes, outcome.as_deref());
        let response = &event["response"];
        let status = identifier(response, "status")?;
        increment_optional(&mut self.response_statuses, status.as_deref());
        if self.representatives.len() >= MAX_REPRESENTATIVES {
            return Ok(());
        }
        let params = event["params"].as_array();
        let columns = response["columns"].as_array();
        let warnings = event["parse_warnings"].as_array();
        let sql = json_str(event, "sql");
        let mut exchange = RewriteMysqlExchangeDetail {
            database: identifier(event, "database")?,
            username: identifier(event, "username")?,
            sql: sql.map(|sql| text_preview(sql, MAX_SQL_BYTES)),
            sql_fingerprint: sql
                .map(crate::config::process_owned_dependencies::mysql::evidence::fingerprint),
            params: params
                .map(|params| {
                    params
                        .iter()
                        .take(MAX_ARGUMENTS_PER_REPRESENTATIVE)
                        .map(parameter)
                        .collect()
                })
                .transpose()?,
            omitted_params: omitted(params, MAX_ARGUMENTS_PER_REPRESENTATIVE),
            outcome,
            response_status: status,
            error_code: json_u64(response, "error_code"),
            error_message: json_str(response, "error_message")
                .map(|s| text_preview(s, MAX_PREVIEW_BYTES)),
            affected_rows: json_u64(response, "affected_rows"),
            row_count: json_u64(response, "row_count"),
            rows_truncated: json_bool(response, "rows_truncated"),
            column_names: columns
                .into_iter()
                .flatten()
                .take(MAX_ARGUMENTS_PER_REPRESENTATIVE)
                .filter_map(|column| json_str(column, "name"))
                .map(|s| text_preview(s, MAX_PREVIEW_BYTES))
                .collect(),
            omitted_columns: omitted(columns, MAX_ARGUMENTS_PER_REPRESENTATIVE),
            parse_warnings: warnings
                .into_iter()
                .flatten()
                .take(MAX_REPRESENTATIVES)
                .filter_map(Value::as_str)
                .map(|s| text_preview(s, MAX_PREVIEW_BYTES))
                .collect(),
            omitted_parse_warnings: omitted(warnings, MAX_REPRESENTATIVES),
            case_dependency_matched_by: identifier(event, "case_dependency_matched_by")?,
            connection_id: None,
            query_sequence: None,
        };
        // Duplicate query/result facts should not crowd out other observations.
        // Add the original record locator after choosing a representative.
        if self.seen.insert(serde_json::to_string(&exchange)?) {
            exchange.connection_id = identifier(event, "connection_id")?;
            exchange.query_sequence = json_u64(event, "query_sequence");
            self.representatives.push(exchange);
        }
        Ok(())
    }
}

pub(super) fn finish(
    operations: BTreeMap<String, OperationBuilder>,
) -> Vec<RewriteMysqlOperationDetail> {
    operations
        .into_iter()
        .map(|(command, builder)| RewriteMysqlOperationDetail {
            command,
            count: builder.count,
            outcomes: builder.outcomes,
            response_statuses: builder.response_statuses,
            omitted_representative_exchanges: builder
                .count
                .saturating_sub(builder.representatives.len()),
            representative_exchanges: builder.representatives,
        })
        .collect()
}

fn omitted(values: Option<&Vec<Value>>, limit: usize) -> usize {
    values.map_or(0, |values| values.len().saturating_sub(limit))
}

fn identifier(event: &Value, key: &str) -> Result<Option<String>> {
    let value = json_str(event, key);
    ensure!(
        value.is_none_or(|s| s.len() <= MAX_PREVIEW_BYTES),
        "MySQL dependency {key} exceeds the supported identity length"
    );
    Ok(value.map(str::to_owned))
}

fn text_preview(value: &str, limit: usize) -> RewriteCapturePreview {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    RewriteCapturePreview {
        encoding: "utf8".to_string(),
        data: value[..end].to_string(),
        original_len: value.len(),
        truncated: end < value.len(),
    }
}

fn parameter(param: &Value) -> Result<RewriteMysqlParameterDetail> {
    let value = param.get("value");
    let rendered = value.map(serde_json::to_string).transpose()?;
    let long = rendered
        .as_ref()
        .is_some_and(|s| s.len() > MAX_PREVIEW_BYTES);
    Ok(RewriteMysqlParameterDetail {
        kind: identifier(param, "kind")?.unwrap_or_else(|| "unknown".into()),
        value: value.filter(|_| !long).cloned(),
        value_preview: rendered
            .filter(|_| long)
            .map(|s| text_preview(&s, MAX_PREVIEW_BYTES)),
        raw: param
            .get("raw")
            .filter(|v| !v.is_null())
            .map(capture_preview)
            .transpose()?,
    })
}

#[cfg(test)]
mod tests;
