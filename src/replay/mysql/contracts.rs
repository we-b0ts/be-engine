//! Complete SQL envelopes and explicit result-value delivery copies.
use super::*;
use crate::policy::{CompiledRule, Slot, Surface};
use crate::policy_evidence::{TargetRole, WitnessMetadata};
use crate::value_contract::json::{AnchorClocks, Comparison};

#[derive(Debug, Clone, Copy)]
pub(in crate::replay) struct ObservedRequest<'a> {
    pub command: &'a str,
    pub sql: Option<&'a str>,
    pub params: Option<&'a [RecordedMysqlValue]>,
    pub started_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    request_started_at: Option<chrono::DateTime<Utc>>,
    command: String,
    sql: Option<String>,
    params: Option<Vec<RecordedMysqlValue>>,
}
impl RequestEnvelope {
    fn observed(request: ObservedRequest<'_>) -> Self {
        Self {
            request_started_at: Some(request.started_at),
            command: request.command.into(),
            sql: request.sql.map(str::to_owned),
            params: request.params.map(<[RecordedMysqlValue]>::to_vec),
        }
    }
    fn recorded(record: &RecordedMysqlExchange) -> Self {
        Self {
            request_started_at: source_started(record),
            command: record.command.clone(),
            sql: record.sql.clone(),
            params: record.params.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    response_delivered_at: Option<chrono::DateTime<Utc>>,
    request: RequestEnvelope,
    outcome: crate::DependencyExchangeOutcome,
    response: RecordedMysqlResponse,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct PreparedDelivery {
    original: Vec<u8>,
    base: ResponseEnvelope,
    rules: Vec<CompiledRule>,
    clocks: AnchorClocks,
    validation: Comparison,
    metadata: Vec<WitnessMetadata>,
}
impl PreparedDelivery {
    pub(in crate::replay) fn render(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<RecordedMysqlResponse> {
        let mut clocks = self.clocks;
        clocks.delivery.target = Some(now);
        materialize_response(
            &self.base.response,
            &self.rules.iter().collect::<Vec<_>>(),
            clocks,
        )
    }
    pub(in crate::replay) fn commit(
        &self,
        owner: &policy::request_contract::RequestContracts,
        response: &RecordedMysqlResponse,
        now: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let mut delivered = self.base.clone();
        delivered.response_delivered_at = Some(now);
        delivered.response = response.clone();
        let target = serde_json::to_vec(&delivered)?;
        for metadata in &self.metadata {
            let mut metadata = metadata.clone();
            metadata.clocks.delivery.target = Some(now);
            owner.record_value_witness(metadata, &self.original, Some(&target))?;
        }
        owner.commit(policy::request_contract::Decision::from_value_comparison(
            self.validation.clone(),
        ));
        Ok(())
    }
}

pub(in crate::replay) fn prepare_delivery(
    owner: &policy::request_contract::RequestContracts,
    case: &str,
    identity: &ReplaySessionIdentity,
    record: &RecordedMysqlExchange,
    delivered: &RecordedMysqlResponse,
    request: ObservedRequest<'_>,
) -> Result<Option<PreparedDelivery>> {
    let rules =
        owner.mysql_compiled_rules(Surface::DependencyResponse, Some(case), identity, record);
    if rules.is_empty()
        || record.outcome != crate::DependencyExchangeOutcome::Response
        || record.response.status != "resultset"
    {
        return Ok(None);
    }
    let clocks = owner.contract_clocks(
        Some(case),
        source_started(record),
        Some(request.started_at),
        record.timestamp,
        None,
    );
    let source_clocks = source_clocks(clocks);
    let validation = validate_response(&record.response, &record.response, &rules, source_clocks)?;
    ensure!(
        validation.passed(),
        "Source SQL response value contract failed: {:?}",
        validation.differences
    );
    // Projection is a native SQL proof. It cannot be inferred from a codec.
    let expected = projected_response(record, request.command, request.sql, request.params)?;
    ensure!(
        &expected == delivered,
        "SQL response copy changed outside the proven projection"
    );
    let original = serde_json::to_vec(&ResponseEnvelope {
        response_delivered_at: record.timestamp,
        request: RequestEnvelope::recorded(record),
        outcome: record.outcome,
        response: record.response.clone(),
    })?;
    let metadata = rules
        .iter()
        .map(|rule| {
            owner.mysql_metadata(
                case,
                identity,
                record,
                (Surface::DependencyResponse, rule.rule.slot.clone()),
                TargetRole::DerivedDelivery,
                clocks,
            )
        })
        .collect();
    Ok(Some(PreparedDelivery {
        original,
        base: ResponseEnvelope {
            response_delivered_at: None,
            request: RequestEnvelope::observed(request),
            outcome: record.outcome,
            response: delivered.clone(),
        },
        rules: rules.into_iter().cloned().collect(),
        clocks,
        validation,
        metadata,
    }))
}

pub(in crate::replay) fn record_request(
    owner: &policy::request_contract::RequestContracts,
    case: &str,
    identity: &ReplaySessionIdentity,
    record: &RecordedMysqlExchange,
    request: ObservedRequest<'_>,
) -> Result<()> {
    if !owner.retains_value_witnesses() || owner.compiled_rules().is_none() {
        return Ok(());
    }
    let source = serde_json::to_vec(&RequestEnvelope::recorded(record))?;
    let actual = serde_json::to_vec(&RequestEnvelope::observed(request))?;
    let clocks = owner.contract_clocks(
        Some(case),
        source_started(record),
        Some(request.started_at),
        None,
        None,
    );
    let rules =
        owner.mysql_compiled_rules(Surface::DependencyRequest, Some(case), identity, record);
    let mut slots = rules
        .iter()
        .map(|rule| rule.rule.slot.clone())
        .collect::<Vec<_>>();
    if slots.is_empty() {
        slots.push(Slot::SqlValue(0));
    }
    for slot in slots {
        owner.record_value_witness(
            owner.mysql_metadata(
                case,
                identity,
                record,
                (Surface::DependencyRequest, slot),
                TargetRole::IndependentTargetObservation,
                clocks,
            ),
            &source,
            Some(&actual),
        )?;
    }
    Ok(())
}

pub(crate) fn source_witness(event: &Value, surface: Surface) -> Result<Vec<u8>> {
    let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
    if surface == Surface::DependencyRequest {
        return Ok(serde_json::to_vec(&RequestEnvelope::recorded(&record))?);
    }
    ensure!(
        surface == Surface::DependencyResponse,
        "invalid SQL witness surface"
    );
    Ok(serde_json::to_vec(&ResponseEnvelope {
        response_delivered_at: record.timestamp,
        request: RequestEnvelope::recorded(&record),
        outcome: record.outcome,
        response: record.response,
    })?)
}

pub(crate) fn validate_witness(
    source: &[u8],
    target: &[u8],
    surface: Surface,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    if surface == Surface::DependencyRequest {
        let source: RequestEnvelope = serde_json::from_slice(source)?;
        let target: RequestEnvelope = serde_json::from_slice(target)?;
        validate_request_clocks(&source, &target, clocks)?;
        ensure!(
            source.command == target.command
                || matches!(
                    (source.command.as_str(), target.command.as_str()),
                    (
                        "COM_QUERY" | "COM_STMT_EXECUTE",
                        "COM_QUERY" | "COM_STMT_EXECUTE"
                    )
                ),
            "SQL command changed outside its native text/prepared query adapter"
        );
        return policy::compare_mysql_values(
            source.sql.as_deref(),
            source.params.as_deref(),
            target.sql.as_deref(),
            target.params.as_deref(),
            rules,
            clocks,
        );
    }
    ensure!(
        surface == Surface::DependencyResponse,
        "invalid SQL witness surface"
    );
    let source: ResponseEnvelope = serde_json::from_slice(source)?;
    let target: ResponseEnvelope = serde_json::from_slice(target)?;
    validate_request_clocks(&source.request, &target.request, clocks)?;
    ensure!(
        source.response_delivered_at == clocks.delivery.source
            && target.response_delivered_at == clocks.delivery.target,
        "SQL response clocks differ from protected metadata"
    );
    ensure!(
        source.outcome == target.outcome,
        "SQL termination outcome changed"
    );
    let record: RecordedMysqlExchange = serde_json::from_value(serde_json::json!({
        "timestamp":source.response_delivered_at,
        "command":source.request.command,"sql":source.request.sql,"params":source.request.params,
        "response":source.response,"outcome":source.outcome
    }))?;
    let base = projected_response(
        &record,
        &target.request.command,
        target.request.sql.as_deref(),
        target.request.params.as_deref(),
    )?;
    let validation = validate_response(
        &record.response,
        &record.response,
        rules,
        source_clocks(clocks),
    )?;
    ensure!(validation.passed(), "Source SQL response contract failed");
    let expected = materialize_response(&base, rules, clocks)?;
    ensure!(
        expected == target.response,
        "derived SQL response differs from its native projection and explicit delivery effects"
    );
    Ok(validation)
}

/// A state-free native SQL Source/Target preflight uses the same request owner.
/// Encoded fields and scalar times share one SQL remainder and clock scope.
pub(crate) fn validate_contract_witness(
    source: &[u8],
    target: &[u8],
    values: &[&CompiledRule],
    native: &[&crate::policy::CompiledNativeRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    let source: RequestEnvelope = serde_json::from_slice(source)?;
    let target: RequestEnvelope = serde_json::from_slice(target)?;
    validate_request_clocks(&source, &target, clocks)?;
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
    policy::compare_mysql_contracts(
        source.sql.as_deref(),
        source.params.as_deref(),
        target.sql.as_deref(),
        target.params.as_deref(),
        values,
        native,
        clocks,
    )
}

pub(crate) fn witness_values(
    raw: &[u8],
    surface: Surface,
    rule: &CompiledRule,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    match (&rule.rule.slot, surface) {
        (Slot::SqlValue(index), Surface::DependencyRequest) => {
            let request: RequestEnvelope = serde_json::from_slice(raw)?;
            let value = policy::mysql_contract_value(
                request.sql.as_deref(),
                request.params.as_deref(),
                rule,
            )?;
            Ok(vec![(index.to_string().into_bytes(), value)])
        }
        (Slot::SqlColumn(column), Surface::DependencyResponse) => {
            let envelope: ResponseEnvelope = serde_json::from_slice(raw)?;
            response_values(&envelope.response, column)
        }
        _ => anyhow::bail!("SQL witness slot and surface disagree"),
    }
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

pub(in crate::replay) fn source_started(
    record: &RecordedMysqlExchange,
) -> Option<chrono::DateTime<Utc>> {
    record
        .timestamp?
        .checked_sub_signed(chrono::TimeDelta::try_milliseconds(
            i64::try_from(record.duration_ms).ok()?,
        )?)
}
fn source_clocks(clocks: AnchorClocks) -> AnchorClocks {
    fn pair(p: crate::value_contract::time::ClockPair) -> crate::value_contract::time::ClockPair {
        crate::value_contract::time::ClockPair {
            source: p.source,
            target: p.source,
        }
    }
    AnchorClocks {
        case: pair(clocks.case),
        dependency: pair(clocks.dependency),
        delivery: pair(clocks.delivery),
    }
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
    projection::query_response(
        record,
        command,
        sql.context("SQL response projection has no target statement")?,
        params,
    )
    .context("SQL statement changes require a complete native projection proof")
}
fn column_index(response: &RecordedMysqlResponse, name: &str) -> Result<usize> {
    ensure!(
        response.status == "resultset" && !response.rows_truncated,
        "SQL encoded column requires a complete resultset"
    );
    let matches = response
        .columns
        .iter()
        .enumerate()
        .filter(|(_, column)| column.column.as_deref().unwrap_or(&column.name) == name)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "SQL encoded column must have one physical identity: {name}"
    );
    Ok(matches[0].0)
}
fn value_bytes(value: &RecordedMysqlValue) -> Result<Option<Vec<u8>>> {
    if value.kind == "null" {
        return Ok(None);
    }
    if value.raw.is_some() {
        return Ok(Some(values::mysql_value_bytes(value)?));
    }
    let text = value
        .value
        .as_ref()
        .and_then(Value::as_str)
        .context("encoded SQL value must retain byte/string type")?;
    ensure!(
        matches!(value.kind.as_str(), "string" | "json" | "binary"),
        "encoded SQL value changed its native value family"
    );
    Ok(Some(text.as_bytes().to_vec()))
}
fn response_values(
    response: &RecordedMysqlResponse,
    column: &str,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let index = column_index(response, column)?;
    response
        .rows
        .iter()
        .enumerate()
        .map(|(row, values)| {
            let value = values.get(index).context("SQL result row is incomplete")?;
            Ok(value_bytes(value)?.map(|bytes| (row.to_string().into_bytes(), bytes)))
        })
        .collect::<Result<Vec<_>>>()
        .map(|values| values.into_iter().flatten().collect())
}
fn validate_response(
    source: &RecordedMysqlResponse,
    target: &RecordedMysqlResponse,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    ensure!(
        source.columns == target.columns && source.rows.len() == target.rows.len(),
        "SQL result metadata or row inventory differs"
    );
    let mut result = Comparison::default();
    for rule in rules {
        let Slot::SqlColumn(column) = &rule.rule.slot else {
            anyhow::bail!("SQL response requires sql_column")
        };
        let source = response_values(source, column)?;
        let target = response_values(target, column)?;
        ensure!(
            source.len() == target.len(),
            "SQL NULL/value presence changed"
        );
        for ((row, source), (other, target)) in source.iter().zip(&target) {
            ensure!(row == other, "SQL row identity changed");
            let next = crate::value_contract::encoded::compare(source, target, &[*rule], clocks)?;
            result.merge_and_validate(next);
        }
    }
    Ok(result)
}
fn materialize_response(
    source: &RecordedMysqlResponse,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<RecordedMysqlResponse> {
    let mut result = source.clone();
    let mut columns = BTreeMap::<String, Vec<&CompiledRule>>::new();
    for rule in rules {
        let Slot::SqlColumn(column) = &rule.rule.slot else {
            anyhow::bail!("SQL response requires sql_column")
        };
        columns.entry(column.clone()).or_default().push(rule);
    }
    for (column, rules) in columns {
        // An independently proven projection can omit a Source column.
        if !source
            .columns
            .iter()
            .any(|c| c.column.as_deref().unwrap_or(&c.name) == column)
        {
            continue;
        }
        let index = column_index(source, &column)?;
        for row in &mut result.rows {
            let value = row.get_mut(index).context("SQL row is incomplete")?;
            let Some(bytes) = value_bytes(value)? else {
                continue;
            };
            let changed = crate::value_contract::encoded::materialize(&bytes, &rules, clocks)?;
            if changed == bytes {
                continue;
            }
            if value.raw.is_some() {
                value.raw = Some(ReplayBodyCapture {
                    encoding: "base64".into(),
                    data: STANDARD.encode(&changed),
                });
                // Keep the native family; raw bytes remain authoritative.
                value.value = None;
            } else {
                value.value = Some(Value::String(
                    String::from_utf8(changed).context("SQL text delivery became non-UTF8")?,
                ));
            }
        }
    }
    Ok(result)
}
