//! Protected offline MySQL witnesses reuse the runtime format comparator.
use super::*;

/// Source coverage inspects decoded SQL value carriers, never envelope clocks
/// or transport metadata. It grants no independent Target observation.
pub(crate) fn validate_source_witness(
    database: Option<&str>,
    source: &[u8],
    surface: Surface,
    policy: &CompiledPolicy,
    clocks: AnchorClocks,
    resource: &crate::policy::Resource,
    metadata: &Metadata,
) -> Result<Comparison> {
    let mut result = validate_witness_with_time_copies(
        database,
        source,
        source,
        surface,
        policy,
        clocks,
        resource,
        &Default::default(),
        "",
        metadata,
    )?;
    let Some(plan) = &policy.global_json else {
        return Ok(result);
    };
    let coverage = |selected: Selection| {
        crate::value_contract::global::compare_logical_with_verified(
            &selected.source,
            &selected.source,
            plan,
            clocks,
            &[],
        )
    };
    if surface == Surface::DependencyRequest {
        let request: RequestEnvelope = serde_json::from_slice(source)?;
        if !matches!(
            request.command.as_str(),
            "COM_QUERY" | "COM_STMT_EXECUTE" | "COM_STMT_PREPARE"
        ) {
            return Ok(result);
        }
        let record: RecordedMysqlExchange = serde_json::from_value(serde_json::json!({
            "command":request.command,"sql":request.sql,"params":request.params,
            "database":database,"response":{"status":"ok"}
        }))?;
        let identity = ReplaySessionIdentity {
            target: Some(TargetKey {
                host: resource.endpoint.host.clone(),
                port: resource.endpoint.port,
            }),
            database: database.map(str::to_owned),
            username: resource.username.clone(),
        };
        let context = RequestContext::new(policy, metadata.clone(), &identity, &record);
        let tokens = record
            .sql
            .as_deref()
            .and_then(crate::mysql::sql::bounds::statement)
            .and_then(|tokens| {
                super::super::super::sql_match::materialize_tokens(
                    tokens,
                    record.params.as_deref().unwrap_or_default(),
                )
            })
            .context("SQL Source coverage requires complete native value bindings")?;
        let origins = crate::mysql::sql::field_bindings::analyze(&tokens, database);
        for (position, token) in tokens.iter().enumerate() {
            if let Some(selected) = context.select(
                token,
                token,
                origins
                    .as_ref()
                    .and_then(|origins| origins.at_token(position)),
                position,
                clocks,
            )? && selected.id == crate::policy::GLOBAL_JSON_ID
            {
                let mut checked = coverage(selected)?;
                checked.scope_schema_clocks(position);
                result.merge_and_validate(checked);
            }
        }
    } else if surface == Surface::DependencyResponse {
        let source: ResponseEnvelope = serde_json::from_slice(source)?;
        for (row_index, row) in source.response.rows.iter().enumerate() {
            for (column_index, value) in row.iter().enumerate() {
                if let Some(selected) = response_selection(
                    policy,
                    &source.response,
                    column_index,
                    value,
                    value,
                    source.request.sql.as_deref(),
                    database,
                    clocks,
                )? && selected.id == crate::policy::GLOBAL_JSON_ID
                {
                    let mut checked = coverage(selected)?;
                    checked.scope_schema_clocks_in(&format!(
                        "mysql-source:{row_index}:{column_index}"
                    ));
                    result.merge_and_validate(checked);
                }
            }
        }
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_witness_with_time_copies(
    database: Option<&str>,
    source: &[u8],
    target: &[u8],
    surface: Surface,
    policy: &CompiledPolicy,
    clocks: AnchorClocks,
    resource: &crate::policy::Resource,
    store: &crate::value_contract::time_copies::TimeCopyStore,
    case: &str,
    metadata: &Metadata,
) -> Result<Comparison> {
    let identity = ReplaySessionIdentity {
        target: Some(TargetKey {
            host: resource.endpoint.host.clone(),
            port: resource.endpoint.port,
        }),
        database: database.map(str::to_owned),
        username: None,
    };
    if surface == Surface::DependencyRequest {
        let source: RequestEnvelope = serde_json::from_slice(source)?;
        let target: RequestEnvelope = serde_json::from_slice(target)?;
        super::validate_request_clocks(&source, &target, clocks)?;
        // Session/control commands such as COM_PING have no SQL value carrier.
        // Keep their native request exact, without inventing a format witness.
        if source.sql.is_none()
            && !matches!(
                source.command.as_str(),
                "COM_QUERY" | "COM_STMT_EXECUTE" | "COM_STMT_PREPARE"
            )
        {
            ensure!(
                source.command == target.command
                    && target.sql.is_none()
                    && source.params == target.params,
                "MySQL non-SQL request changed"
            );
            return Ok(Comparison::default());
        }
        let record: RecordedMysqlExchange = serde_json::from_value(
            serde_json::json!({"command":source.command,"sql":source.sql,"params":source.params,"response":{"status":"ok"}}),
        )?;
        ensure!(
            record.command == target.command
                || matches!(
                    (record.command.as_str(), target.command.as_str()),
                    (
                        "COM_QUERY" | "COM_STMT_EXECUTE",
                        "COM_QUERY" | "COM_STMT_EXECUTE"
                    )
                ),
            "MySQL command changed outside native text/prepared adapter"
        );
        let context = RequestContext::new(policy, metadata.clone(), &identity, &record);
        let tokens = record
            .sql
            .as_deref()
            .and_then(crate::mysql::sql::bounds::statement)
            .and_then(|tokens| {
                super::super::super::sql_match::materialize_tokens(
                    tokens,
                    record.params.as_deref().unwrap_or_default(),
                )
            })
            .context("SQL request witness requires a bounded statement and complete bindings")?;
        if !context.selects_values(&tokens, database, clocks)? {
            let mut cache = super::super::super::sql_match::cache::SqlCache::default();
            let baseline = record.sql.as_deref().and_then(|sql| {
                cache
                    .get(sql)
                    .bind(&record.command, record.params.as_deref())
            });
            let actual = target.sql.as_deref().and_then(|sql| {
                cache
                    .get(sql)
                    .bind(&target.command, target.params.as_deref())
            });
            if baseline
                .zip(actual)
                .is_some_and(|(source, target)| target.matches(&source, false))
            {
                return Ok(Comparison::default());
            }
        }
        return policy::compare_mysql_with_automatic(
            database,
            record.sql.as_deref(),
            record.params.as_deref(),
            target.sql.as_deref(),
            target.params.as_deref(),
            &[],
            &[],
            clocks,
            Some(policy::MysqlTimeCopyProofs::stored(store, case)),
            &context,
        );
    }
    ensure!(
        surface == Surface::DependencyResponse,
        "invalid MySQL global witness surface"
    );
    let source: ResponseEnvelope = serde_json::from_slice(source)?;
    let target: ResponseEnvelope = serde_json::from_slice(target)?;
    super::validate_request_clocks(&source.request, &target.request, clocks)?;
    ensure!(
        source.response_delivered_at == clocks.delivery.source
            && target.response_delivered_at == clocks.delivery.target,
        "MySQL response clocks differ from protected metadata"
    );
    ensure!(
        source.outcome == target.outcome,
        "MySQL response outcome changed"
    );
    let record: RecordedMysqlExchange = serde_json::from_value(serde_json::json!({
        "command":source.request.command,"sql":source.request.sql,"params":source.request.params,
        "response":source.response,"outcome":source.outcome,"timestamp":source.response_delivered_at,
    }))?;
    let base = if let Ok(projected) = super::projected_response(
        &record,
        &target.request.command,
        target.request.sql.as_deref(),
        target.request.params.as_deref(),
    ) {
        projected
    } else {
        let context = RequestContext::new(policy, metadata.clone(), &identity, &record);
        let request = policy::compare_mysql_with_automatic(
            database,
            record.sql.as_deref(),
            record.params.as_deref(),
            target.request.sql.as_deref(),
            target.request.params.as_deref(),
            &[],
            &[],
            clocks,
            None,
            &context,
        )?;
        ensure!(
            request.passed(),
            "MySQL response request changed outside global field contracts"
        );
        record.response.clone()
    };
    compare_response(
        policy,
        &base,
        &target.response,
        source.request.sql.as_deref(),
        database,
        clocks,
    )
}

pub(in crate::replay) fn validate_source_record(
    owner: &policy::request_contract::RequestContracts,
    identity: &ReplaySessionIdentity,
    record: &RecordedMysqlExchange,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    let Some(policy) = owner
        .compiled_rules()
        .filter(|policy| policy.global_json.is_some() || policy.mysql.is_some())
    else {
        return Ok(Comparison::default());
    };
    let clocks = super::source_clocks(clocks);
    let context = RequestContext::new(
        policy,
        owner
            .mysql_automatic
            .lock()
            .expect("MySQL inference metadata")
            .clone(),
        identity,
        record,
    );
    let mut result = if record.sql.is_some()
        && matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
    {
        policy::compare_mysql_with_automatic(
            record.database.as_deref(),
            record.sql.as_deref(),
            record.params.as_deref(),
            record.sql.as_deref(),
            record.params.as_deref(),
            &[],
            &[],
            clocks,
            None,
            &context,
        )?
    } else {
        Comparison::default()
    };
    if record.response.status == "resultset" {
        result.merge_and_validate(compare_response(
            policy,
            &record.response,
            &record.response,
            record.sql.as_deref(),
            record.database.as_deref(),
            clocks,
        )?);
    }
    Ok(result)
}
