use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use super::{CommandProtocolCounts, HttpEventCounts, MysqlEventCounts, ReplayEventCounts};

pub(super) fn read(report: &Value, version: u64, path: &Path) -> Result<ReplayEventCounts> {
    let success_detail_limit = if version >= 5 {
        Some(required_usize(report, "success_detail_limit", path)?)
    } else {
        None
    };
    if success_detail_limit == Some(0) {
        bail!(
            "replay report {} success_detail_limit must be positive",
            path.display()
        );
    }
    Ok(ReplayEventCounts {
        mysql: MysqlEventCounts {
            connections: required_usize(report, "connections", path)?,
            builtin_queries: success_count(
                report,
                "builtin_queries",
                "builtin_query_count",
                success_detail_limit,
                path,
            )?,
            matched_queries: success_count(
                report,
                "matched_queries",
                "matched_query_count",
                success_detail_limit,
                path,
            )?,
            unmatched_queries: required_len(report, "unmatched_queries", path)?,
            unsupported_commands: required_len(report, "unsupported_commands", path)?,
            unused_case_exchanges: required_len(report, "unused_case_exchanges", path)?,
            unused_bootstrap_exchanges: required_len(report, "unused_bootstrap_exchanges", path)?,
            metadata_warnings: required_len(report, "metadata_warnings", path)?,
        },
        http: HttpEventCounts {
            matched_exchanges: success_count(
                report,
                "matched_http_exchanges",
                "matched_http_exchange_count",
                success_detail_limit,
                path,
            )?,
            unmatched_requests: required_len(report, "unmatched_http_requests", path)?,
            unsupported_exchanges: required_len(report, "unsupported_http_exchanges", path)?,
            unused_case_exchanges: required_len(report, "unused_case_http_exchanges", path)?,
            allowed_unused_case_exchanges: optional_len(
                report,
                "allowed_unused_case_http_exchanges",
                path,
            )?,
            unused_bootstrap_exchanges: required_len(
                report,
                "unused_bootstrap_http_exchanges",
                path,
            )?,
        },
        redis: protocol_counts(report, "redis", version >= 3, success_detail_limit, path)?,
        memcached: protocol_counts(
            report,
            "memcached",
            version >= 3,
            success_detail_limit,
            path,
        )?,
        kafka: protocol_counts(report, "kafka", version >= 3, success_detail_limit, path)?,
    })
}

fn protocol_counts(
    report: &Value,
    protocol: &str,
    required: bool,
    success_detail_limit: Option<usize>,
    path: &Path,
) -> Result<CommandProtocolCounts> {
    let Some(value) = report.get(protocol) else {
        if required {
            bail!(
                "replay report {} version 3 or newer is missing {protocol}",
                path.display()
            );
        }
        return Ok(CommandProtocolCounts::default());
    };
    if !value.is_object() {
        bail!(
            "replay report {} field {protocol} must be an object",
            path.display()
        );
    }
    Ok(CommandProtocolCounts {
        connections: required_usize(value, "connections", path)?,
        matched: success_count(
            value,
            "matched",
            "matched_count",
            success_detail_limit,
            path,
        )?,
        unmatched: required_len(value, "unmatched", path)?,
        unsupported: required_len(value, "unsupported", path)?,
        unsafe_events: required_len(value, "unsafe_events", path)?,
        unused_case: required_len(value, "unused_case", path)?,
        unused_bootstrap: required_len(value, "unused_bootstrap", path)?,
        warnings: optional_len(value, "warnings", path)?,
    })
}

fn success_count(
    value: &Value,
    details_field: &str,
    count_field: &str,
    detail_limit: Option<usize>,
    path: &Path,
) -> Result<usize> {
    let retained = required_len(value, details_field, path)?;
    let Some(detail_limit) = detail_limit else {
        return Ok(retained);
    };
    let total = required_usize(value, count_field, path)?;
    if retained > detail_limit || retained > total {
        bail!(
            "replay report {} field {details_field} retains {retained} entries but limit/count are {detail_limit}/{total}",
            path.display()
        );
    }
    Ok(total)
}

fn required_len(value: &Value, field: &str, path: &Path) -> Result<usize> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| {
            anyhow!(
                "replay report {} field {field} must be an array",
                path.display()
            )
        })
}

fn optional_len(value: &Value, field: &str, path: &Path) -> Result<usize> {
    match value.get(field) {
        Some(_) => required_len(value, field, path),
        None => Ok(0),
    }
}

fn required_usize(value: &Value, field: &str, path: &Path) -> Result<usize> {
    let number = value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        anyhow!(
            "replay report {} field {field} must be a non-negative integer",
            path.display()
        )
    })?;
    usize::try_from(number).with_context(|| {
        format!(
            "replay report {} field {field} does not fit usize",
            path.display()
        )
    })
}
