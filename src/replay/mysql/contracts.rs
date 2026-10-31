//! Complete SQL envelopes and explicit result-value delivery copies.
use super::*;
use crate::policy::{CompiledRule, Slot, Surface};
use crate::policy_evidence::{TargetRole, WitnessMetadata};
use crate::value_contract::json::{AnchorClocks, Comparison};
pub(in crate::replay) mod automatic;
mod delivery;
pub(in crate::replay) mod fields;
mod preflight_identity;
pub(in crate::replay) mod time_copies;
mod value_view;
pub(crate) use preflight_identity::{IdentityPreflight, normalize_identity_witnesses};
pub(crate) use value_view::mysql_witness_sql_value;

#[derive(Debug, Clone, Copy)]
pub(in crate::replay) struct ObservedRequest<'a> {
    pub observation_id: Option<uuid::Uuid>,
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
    observation_id: uuid::Uuid,
    original: Arc<[u8]>,
    base: ResponseEnvelope,
    clocks: AnchorClocks,
    metadata: Vec<WitnessMetadata>,
    database: Option<String>,
    identities: Option<(policy::request_contract::RequestContracts, String)>,
}
impl PreparedDelivery {
    pub(in crate::replay) fn render(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<(
        RecordedMysqlResponse,
        Option<crate::value_contract::identities::IdentityDecision>,
    )> {
        let mut clocks = self.clocks;
        clocks.delivery.target = Some(now);
        delivery::materialize_response(
            &self.base.response,
            clocks,
            self.base.request.sql.as_deref(),
            self.database.as_deref(),
            self.identities
                .as_ref()
                .map(|(owner, case)| (owner, case.as_str())),
        )
    }
    pub(in crate::replay) fn commit(
        &self,
        owner: &policy::request_contract::RequestContracts,
        response: &RecordedMysqlResponse,
        now: chrono::DateTime<Utc>,
        identity: Option<crate::value_contract::identities::IdentityDecision>,
    ) -> Result<()> {
        let mut delivered = self.base.clone();
        delivered.response_delivered_at = Some(now);
        delivered.response = response.clone();
        let target = serde_json::to_vec(&delivered)?;
        for metadata in &self.metadata {
            let mut metadata = metadata.clone();
            metadata.clocks.delivery.target = Some(now);
            owner.record_delivery_witness(
                &self.observation_id.to_string(),
                metadata,
                &self.original,
                &target,
            )?;
        }
        let comparison = automatic::compare_response(
            owner
                .compiled_rules()
                .context("SQL delivery lost its global policy")?,
            &self.base.response,
            response,
            self.base.request.sql.as_deref(),
            self.database.as_deref(),
            AnchorClocks {
                delivery: crate::value_contract::time::ClockPair {
                    target: Some(now),
                    ..self.clocks.delivery
                },
                ..self.clocks
            },
        )?;
        ensure!(comparison.passed(), "SQL delivered value contract failed");
        let mut decision = policy::request_contract::Decision::from_value_comparison(comparison);
        decision.identity = identity;
        owner.commit(decision)?;
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
    let automatic = owner
        .compiled_rules()
        .filter(|policy| policy.global_json.is_some() || policy.mysql.is_some());
    if automatic.is_none()
        || record.outcome != crate::DependencyExchangeOutcome::Response
        || record.response.status != "resultset"
    {
        return Ok(None);
    }
    let mut original = record.clone();
    original.response = record.response.materialize()?;
    let record = &original;
    let clocks = owner.contract_clocks(
        Some(case),
        source_started(record),
        Some(request.started_at),
        record.timestamp,
        None,
    );
    let source_clocks = source_clocks(clocks);
    let validation = automatic::compare_response(
        automatic.expect("global MySQL mode"),
        &record.response,
        &record.response,
        record.sql.as_deref(),
        record.database.as_deref(),
        source_clocks,
    )?;
    ensure!(
        validation.passed(),
        "Source SQL response value contract failed: {:?}",
        validation.differences
    );
    // Projection is a native SQL proof. It cannot be inferred from a codec.
    let expected = delivery::projected_response(owner, case, identity, record, request, clocks)?;
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
    let metadata = vec![owner.mysql_metadata(
        case,
        identity,
        record,
        (Surface::DependencyResponse, Slot::SqlColumn(String::new())),
        TargetRole::DerivedDelivery,
        clocks,
    )];
    let identities = Some((owner.clone(), case.to_owned()));
    Ok(Some(PreparedDelivery {
        observation_id: uuid::Uuid::new_v4(),
        original: original.into(),
        base: ResponseEnvelope {
            response_delivered_at: None,
            request: RequestEnvelope::observed(request),
            outcome: record.outcome,
            response: delivered.clone(),
        },
        clocks,
        metadata,
        database: identity.database.clone(),
        identities,
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
    let Some(observation_id) = request.observation_id else {
        return Ok(());
    };
    let clocks = owner.contract_clocks(
        Some(case),
        source_started(record),
        Some(request.started_at),
        None,
        None,
    );
    let slots = [Slot::SqlValue(0)];
    for slot in slots {
        let metadata = owner.mysql_metadata(
            case,
            identity,
            record,
            (Surface::DependencyRequest, slot),
            TargetRole::IndependentTargetObservation,
            clocks,
        );
        let id = observation_id.to_string();
        if owner.associate_value_witness(&metadata, &id, None)?
            == crate::policy_evidence::AssociationOutcome::SourceRequired
        {
            let source = serde_json::to_vec(&RequestEnvelope::recorded(record))?;
            owner.associate_value_witness(&metadata, &id, Some(&source))?;
        }
    }
    Ok(())
}

pub(in crate::replay) fn record_target(
    owner: &policy::request_contract::RequestContracts,
    case: &str,
    identity: &ReplaySessionIdentity,
    request: ObservedRequest<'_>,
) -> Result<crate::policy_evidence::ObservationRetention> {
    if !owner.retains_value_witnesses() {
        return Ok(crate::policy_evidence::ObservationRetention::Unavailable);
    }
    let resource = identity
        .target
        .as_ref()
        .map(|target| crate::policy::Resource {
            protocol: crate::policy::Protocol::Mysql,
            endpoint: crate::policy::Endpoint {
                host: target.host.clone(),
                port: target.port,
            },
            database: identity.database.clone().map(crate::policy::Database::Name),
            username: identity.username.clone(),
        });
    owner.record_independent_request(
        &request
            .observation_id
            .context("SQL Target observation identity is missing")?
            .to_string(),
        case,
        resource,
        request.command,
        request.started_at,
        &serde_json::to_vec(&RequestEnvelope::observed(request))?,
    )
}

pub(in crate::replay) fn record_unanchored_target(
    observations: &crate::replay::target_observation::TargetObservations,
    case: Option<&str>,
    identity: &ReplaySessionIdentity,
    request: ObservedRequest<'_>,
) -> Result<crate::policy_evidence::ObservationRetention> {
    let resource = identity
        .target
        .as_ref()
        .map(|target| crate::policy::Resource {
            protocol: crate::policy::Protocol::Mysql,
            endpoint: crate::policy::Endpoint {
                host: target.host.clone(),
                port: target.port,
            },
            database: identity.database.clone().map(crate::policy::Database::Name),
            username: identity.username.clone(),
        });
    observations.record(
        request
            .observation_id
            .context("SQL Target observation identity missing")?,
        case,
        resource,
        request.command,
        request.started_at,
        &serde_json::to_vec(&RequestEnvelope::observed(request))?,
    )
}

pub(crate) fn source_witness(event: &Value, surface: Surface) -> Result<Vec<u8>> {
    let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
    source_witness_from_record(&record, surface)
}

pub(in crate::replay) fn source_witness_from_record(
    record: &RecordedMysqlExchange,
    surface: Surface,
) -> Result<Vec<u8>> {
    if surface == Surface::DependencyRequest {
        return Ok(serde_json::to_vec(&RequestEnvelope::recorded(record))?);
    }
    ensure!(
        surface == Surface::DependencyResponse,
        "invalid SQL witness surface"
    );
    response_witness(
        RequestEnvelope::recorded(record),
        record.timestamp,
        record.outcome,
        &record.response,
    )
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
