//! Complete SQL envelopes and explicit result-value delivery copies.
use super::*;
use crate::policy::{CompiledRule, Slot, Surface};
use crate::value_contract::json::{AnchorClocks, Comparison};
pub(crate) mod automatic;
pub(crate) mod fields;
pub(crate) mod time_copies;
mod value_view;
pub(crate) use value_view::mysql_witness_sql_value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    request_started_at: Option<chrono::DateTime<Utc>>,
    command: String,
    sql: Option<String>,
    params: Option<Vec<RecordedMysqlValue>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    response_delivered_at: Option<chrono::DateTime<Utc>>,
    request: RequestEnvelope,
    outcome: crate::DependencyExchangeOutcome,
    response: RecordedMysqlResponse,
}

pub(crate) fn source_witness(event: &Value, surface: Surface) -> Result<Vec<u8>> {
    traffic_protocol_mysql::witness::source_payload(event, surface.dependency_side()?)
}

pub(crate) fn source_witness_from_record(
    record: &RecordedMysqlExchange,
    surface: Surface,
) -> Result<Vec<u8>> {
    traffic_protocol_mysql::witness::from_record(record, surface.dependency_side()?)
}

fn response_witness(
    request: RequestEnvelope,
    response_delivered_at: Option<chrono::DateTime<Utc>>,
    outcome: crate::DependencyExchangeOutcome,
    response: &RecordedMysqlResponse,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct OriginalResponse<'a> {
        response_delivered_at: Option<chrono::DateTime<Utc>>,
        request: RequestEnvelope,
        outcome: crate::DependencyExchangeOutcome,
        response: &'a RecordedMysqlResponse,
    }
    Ok(serde_json::to_vec(&OriginalResponse {
        response_delivered_at,
        request,
        outcome,
        response,
    })?)
}

/// A state-free native SQL Source/Target preflight uses the same request owner.
/// Encoded fields and scalar times share one SQL remainder and clock scope.
pub(crate) fn validate_contract_witness(
    database: Option<&str>,
    source: &[u8],
    target: &[u8],
    values: &[&CompiledRule],
    native: &[&crate::policy::CompiledNativeRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    validate_contract_candidate(database, source, target, values, native, clocks)?
        .context("SQL witness statements are structurally unrelated")
}

/// Search edges retain every visited statement in a resource/command scope.
/// Exclude structurally different statements before validating scalar values;
/// an excluded edge supplies no independent Target validation.
pub(crate) fn validate_contract_candidate(
    // Source and Target share this observed default schema; missing evidence
    // grants physical field permissions only to fully qualified statements.
    database: Option<&str>,
    source: &[u8],
    target: &[u8],
    values: &[&CompiledRule],
    native: &[&crate::policy::CompiledNativeRule],
    clocks: AnchorClocks,
) -> Result<Option<Comparison>> {
    validate_contract_candidate_inner(database, source, target, values, native, clocks, None)
}

fn validate_contract_candidate_inner(
    // Source and Target share this observed default schema; missing evidence
    // grants physical field permissions only to fully qualified statements.
    database: Option<&str>,
    source: &[u8],
    target: &[u8],
    values: &[&CompiledRule],
    native: &[&crate::policy::CompiledNativeRule],
    clocks: AnchorClocks,
    copies: Option<policy::MysqlTimeCopyProofs<'_>>,
) -> Result<Option<Comparison>> {
    let source: RequestEnvelope = serde_json::from_slice(source)?;
    let target: RequestEnvelope = serde_json::from_slice(target)?;
    if !related_sql_requests(&source, &target, clocks)? {
        return Ok(None);
    }
    policy::compare_mysql_contracts_with_time_copies(
        database,
        source.sql.as_deref(),
        source.params.as_deref(),
        target.sql.as_deref(),
        target.params.as_deref(),
        values,
        native,
        clocks,
        copies,
    )
    .map(Some)
}

/// Candidate selection shares native request clocks and bounded SQL shape;
/// exclusion is missing Target validation, never permission to match at runtime.
pub(crate) fn request_candidates_related(
    source: &[u8],
    target: &[u8],
    clocks: AnchorClocks,
) -> Result<bool> {
    related_sql_requests(
        &serde_json::from_slice(source)?,
        &serde_json::from_slice(target)?,
        clocks,
    )
}

fn related_sql_requests(
    source: &RequestEnvelope,
    target: &RequestEnvelope,
    clocks: AnchorClocks,
) -> Result<bool> {
    validate_request_clocks(source, target, clocks)?;
    ensure!(
        matches!(
            (source.command.as_str(), target.command.as_str()),
            (
                "COM_QUERY" | "COM_STMT_EXECUTE",
                "COM_QUERY" | "COM_STMT_EXECUTE"
            )
        ),
        "native SQL time values require the query adapter"
    );
    structurally_related(source, target)
}

fn structurally_related(source: &RequestEnvelope, target: &RequestEnvelope) -> Result<bool> {
    let statement = |request: &RequestEnvelope| {
        crate::mysql::sql::bounds::statement(
            request
                .sql
                .as_deref()
                .context("SQL witness has no statement")?,
        )
        .context("SQL witness statement is invalid or exceeds the supported bounds")
    };
    let source_tokens = statement(source)?;
    let target_tokens = statement(target)?;
    let scalar = |token: &crate::mysql::sql::Token| {
        token.is_value() || *token == crate::mysql::sql::Token::Placeholder
    };
    Ok(source_tokens.len() == target_tokens.len()
        && source_tokens
            .iter()
            .zip(&target_tokens)
            .all(|(source, target)| source == target || scalar(source) && scalar(target)))
}

fn validate_request_clocks(
    source: &RequestEnvelope,
    target: &RequestEnvelope,
    clocks: AnchorClocks,
) -> Result<()> {
    ensure!(
        source.request_started_at == clocks.dependency.source
            && target.request_started_at == clocks.dependency.target,
        "SQL request clocks differ from protected metadata"
    );
    Ok(())
}

pub(crate) fn source_started(record: &RecordedMysqlExchange) -> Option<chrono::DateTime<Utc>> {
    record.source_started_at()
}
fn source_clocks(clocks: AnchorClocks) -> AnchorClocks {
    fn pair(p: crate::value_contract::time::ClockPair) -> crate::value_contract::time::ClockPair {
        crate::value_contract::time::ClockPair {
            source: p.source,
            target: p.source,
        }
    }
    AnchorClocks::for_request(
        pair(clocks.case),
        pair(clocks.dependency),
        pair(clocks.delivery),
    )
}
fn projected_response(
    record: &RecordedMysqlExchange,
    command: &str,
    sql: Option<&str>,
    params: Option<&[RecordedMysqlValue]>,
) -> Result<RecordedMysqlResponse> {
    if record.command == command
        && record.sql.as_deref() == sql
        && record.params.as_deref() == params
    {
        return Ok(record.response.clone());
    }
    let sql = sql.context("SQL response projection has no target statement")?;
    projection::query_response(record, command, sql, params)
        .or_else(|| {
            // Delivery and offline witnesses must retain the same native predicate
            // proof used by request matching, independently of global value rules.
            let mut cache = sql_match::cache::SqlCache::default();
            let source = cache
                .get(record.sql.as_deref()?)
                .bind(&record.command, record.params.as_deref())?;
            let target = cache.get(sql).bind(command, params)?;
            projection::semantic_response(record, &source, &target)
        })
        .context("SQL statement changes require a complete native projection proof")
}
