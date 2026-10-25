//! Retain globally selected time leaves using real result-column provenance.
use super::*;

pub(super) fn columns(
    owner: &RequestContracts,
    identity: &ReplaySessionIdentity,
    original: &RecordedMysqlExchange,
    projected: &RecordedMysqlResponse,
    sql: Option<&str>,
) -> Result<Vec<Column>> {
    let Some(policy) = owner
        .compiled_rules()
        .filter(|policy| policy.global_json.is_some() || policy.mysql.is_some())
    else {
        return Ok(vec![]);
    };
    let clocks = owner.contract_clocks(
        None,
        source_started(original),
        None,
        original.timestamp,
        None,
    );
    columns_for_policy(policy, identity, original, projected, sql, clocks)
}

fn columns_for_policy(
    policy: &crate::policy::CompiledPolicy,
    identity: &ReplaySessionIdentity,
    original: &RecordedMysqlExchange,
    projected: &RecordedMysqlResponse,
    sql: Option<&str>,
    clocks: AnchorClocks,
) -> Result<Vec<Column>> {
    if projected.status != "resultset" || projected.rows_truncated || original.timestamp.is_none() {
        return Ok(vec![]);
    }
    let analysis = analysis(projected, sql, identity.database.as_deref());
    let mut columns = Vec::new();
    let mut leaf_count = 0usize;
    for index in 0..projected.columns.len() {
        let Some(origin) = fields::response_origin(projected, index, analysis.as_deref()) else {
            continue;
        };
        for (row_index, row) in projected.rows.iter().enumerate() {
            let value = row
                .get(index)
                .context("global time read result row is incomplete")?;
            let Some(selected) = automatic::response_selection(
                policy,
                projected,
                index,
                value,
                value,
                sql,
                identity.database.as_deref(),
                clocks,
            )?
            else {
                continue;
            };
            let leaves = automatic::time_leaves(&selected, policy, clocks)?;
            leaf_count = leaf_count.saturating_add(leaves.len());
            ensure!(
                leaf_count <= 4096,
                "global SQL time read exceeds 4096 selected leaves"
            );
            if leaves.is_empty() {
                continue;
            }
            let codec = if selected.id == automatic::MYSQL_ID {
                crate::policy::Codec::Scalar
            } else {
                crate::policy::Codec::Json
            };
            let bytes = fields::value_bytes(value, &codec)?
                .context("global time read payload disappeared")?;
            columns.push(Column {
                index,
                origin: origin.clone(),
                codec,
                rows: vec![Row {
                    index: row_index,
                    digest: Sha256::digest(&bytes).into(),
                    leaves,
                }],
            });
        }
    }
    Ok(columns)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn delivered_witness_time_copies(
    source: &[u8],
    target: &[u8],
    policy: &crate::policy::CompiledPolicy,
    resource: &crate::policy::Resource,
    database: Option<&str>,
    clocks: AnchorClocks,
    record: &mut Recorder<'_>,
) -> Result<usize> {
    let source: ResponseEnvelope = serde_json::from_slice(source)?;
    let target: ResponseEnvelope = serde_json::from_slice(target)?;
    super::super::validate_request_clocks(&source.request, &target.request, clocks)?;
    ensure!(
        source.response_delivered_at == clocks.delivery.source
            && target.response_delivered_at == clocks.delivery.target,
        "delivered MySQL input clocks differ from protected metadata"
    );
    if source.outcome != crate::DependencyExchangeOutcome::Response
        || target.outcome != source.outcome
    {
        return Ok(0);
    }
    let original: RecordedMysqlExchange = serde_json::from_value(serde_json::json!({
        "command":source.request.command,"sql":source.request.sql,"params":source.request.params,
        "database":database,"response":source.response,"outcome":source.outcome,"timestamp":source.response_delivered_at,
    }))?;
    let projected = if let Ok(response) = projected_response(
        &original,
        &target.request.command,
        target.request.sql.as_deref(),
        target.request.params.as_deref(),
    ) {
        response
    } else {
        original.response.clone()
    };
    let identity = ReplaySessionIdentity {
        target: Some(TargetKey {
            host: resource.endpoint.host.clone(),
            port: resource.endpoint.port,
        }),
        database: database.map(str::to_owned),
        username: resource.username.clone(),
    };
    let validation = automatic::compare_input_response(
        policy,
        &projected,
        &target.response,
        target.request.sql.as_deref(),
        database,
        clocks,
    )?;
    ensure!(
        validation.passed(),
        "MySQL delivered input changed outside selected temporal and identity fields"
    );
    let columns = columns_for_policy(
        policy,
        &identity,
        &original,
        &projected,
        target.request.sql.as_deref(),
        clocks,
    )?;
    if columns.is_empty() {
        return Ok(0);
    }
    let pending = PreparedRead {
        owner: None,
        case: String::new(),
        host: resource.endpoint.host.clone(),
        port: resource.endpoint.port,
        columns,
        row_count: projected.rows.len(),
        source_completed_at: source.response_delivered_at,
        witness: None,
    };
    pending.observe_delivered(
        &identity,
        &target.response,
        target.request.sql.as_deref(),
        record,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn actual_historical_input_yields_copy_facts_without_new_relative_offset() {
        let policy=crate::policy::parse_and_compile_policy("format: traffic-policy/v2\njson:\n  fields:\n    /created_at: {kind: time, formats: [unix_seconds]}\n").unwrap();
        let response:RecordedMysqlResponse=serde_json::from_value(json!({"status":"resultset","columns":[
            {"name":"payload","database":"app","table":"tasks","column":"payload","sql_type":"JSON","family":"json"},
            {"name":"day","database":"app","table":"tasks","column":"day","sql_type":"DATE","family":"date"}
        ],"rows":[[{"kind":"string","value":"{\"created_at\":946684800,\"stable\":7}"},{"kind":"date","value":"2000-01-01"}]]})).unwrap();
        let source_start = "2020-01-01T00:00:00Z".parse().unwrap();
        let target_start = "2026-01-01T00:00:00Z".parse().unwrap();
        let source = ResponseEnvelope {
            response_delivered_at: Some(source_start),
            request: RequestEnvelope {
                request_started_at: Some(source_start),
                command: "COM_QUERY".into(),
                sql: Some("SELECT payload,day FROM tasks".into()),
                params: None,
            },
            outcome: crate::DependencyExchangeOutcome::Response,
            response: response.clone(),
        };
        let mut target = source.clone();
        target.response_delivered_at = Some(target_start);
        target.request.request_started_at = Some(target_start);
        let clocks = AnchorClocks {
            dependency: crate::value_contract::time::ClockPair {
                source: Some(source_start),
                target: Some(target_start),
            },
            delivery: crate::value_contract::time::ClockPair {
                source: Some(source_start),
                target: Some(target_start),
            },
            ..Default::default()
        };
        let resource = crate::policy::Resource {
            protocol: crate::policy::Protocol::Mysql,
            endpoint: crate::policy::Endpoint {
                host: "db.test".into(),
                port: 3306,
            },
            database: Some(crate::policy::Database::Name("app".into())),
            username: None,
        };
        let mut facts = 0usize;
        let count = delivered_witness_time_copies(
            &serde_json::to_vec(&source).unwrap(),
            &serde_json::to_vec(&target).unwrap(),
            &policy,
            &resource,
            Some("app"),
            clocks,
            &mut |_, _, _, _, a, b, _| {
                assert_eq!(a, b);
                facts += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(count, 2);
        assert_eq!(facts, 2);
        target.response.rows[0][0].value = Some(json!("{\"created_at\":946684800,\"stable\":8}"));
        assert!(
            delivered_witness_time_copies(
                &serde_json::to_vec(&source).unwrap(),
                &serde_json::to_vec(&target).unwrap(),
                &policy,
                &resource,
                Some("app"),
                clocks,
                &mut |_, _, _, _, _, _, _| Ok(())
            )
            .is_err()
        );
    }
}
