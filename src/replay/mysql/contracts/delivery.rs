//! Physical result-field delivery uses one decoded carrier and a bounded case mapping.
use super::*;

pub(super) fn projected_response(
    owner: &policy::request_contract::RequestContracts,
    case: &str,
    identity: &ReplaySessionIdentity,
    record: &RecordedMysqlExchange,
    request: ObservedRequest<'_>,
    clocks: AnchorClocks,
) -> Result<RecordedMysqlResponse> {
    if let Ok(response) =
        super::projected_response(record, request.command, request.sql, request.params)
    {
        return Ok(response);
    }
    // A field contract can change predicate values while leaving the SELECT
    // projection and every other token intact. The projection adapter alone
    // intentionally cannot grant that value permission.
    if let Some(policy) = owner
        .compiled_rules()
        .filter(|policy| policy.global_json.is_some() || policy.mysql.is_some())
    {
        let context = automatic::RequestContext::new(
            policy,
            owner
                .mysql_automatic
                .lock()
                .expect("MySQL inference metadata")
                .clone(),
            identity,
            record,
        );
        let comparison = policy::compare_mysql_with_automatic(
            record.database.as_deref(),
            record.sql.as_deref(),
            record.params.as_deref(),
            request.sql,
            request.params,
            &[],
            &[],
            clocks,
            None,
            &context,
        )?;
        ensure!(
            comparison.passed(),
            "SQL global predicate field contract failed"
        );
        owner.identity_decision(case, &comparison)?;
        return Ok(record.response.clone());
    }
    anyhow::bail!("SQL response has no proven projection or global content strategy")
}

pub(super) fn materialize_response(
    source: &RecordedMysqlResponse,
    clocks: AnchorClocks,
    sql: Option<&str>,
    database: Option<&str>,
    identities: Option<(&policy::request_contract::RequestContracts, &str)>,
) -> Result<(
    RecordedMysqlResponse,
    Option<crate::value_contract::identities::IdentityDecision>,
)> {
    let Some((owner, case)) = identities else {
        return Ok((source.clone(), None));
    };
    let Some(policy) = owner.compiled_rules() else {
        return Ok((source.clone(), None));
    };
    let mut pending: Option<crate::value_contract::identities::IdentityDecision> = None;
    let mut result = source.clone();
    for index in 0..source.columns.len() {
        for row in &mut result.rows {
            let value = row.get_mut(index).context("SQL row is incomplete")?;
            let Some(selected) = automatic::response_selection(
                policy, source, index, value, value, sql, database, clocks,
            )?
            else {
                continue;
            };
            let (logical, decision) =
                automatic::translate_selection(owner, case, &selected, clocks)?;
            if let Some(decision) = decision {
                if let Some(pending) = &mut pending {
                    pending.merge(decision)?
                } else {
                    pending = Some(decision)
                }
            }
            if logical != selected.source {
                *value =
                    automatic::write_value(value, logical, selected.id == automatic::MYSQL_ID)?;
            }
        }
    }
    let mut checked = policy::request_contract::Decision::default();
    if let Some(pending) = pending {
        owner.merge_identity_decision(&mut checked, pending)?;
    }
    Ok((result, checked.identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identity_inputs_publish_only_after_their_delivery_is_committed() {
        let id = "11111111-1111-4111-8111-111111111111";
        let alternate = "22222222-2222-4222-8222-222222222222";
        let compiled = crate::policy::parse_and_compile_policy(
            "format: traffic-policy/v3\njson: {fields: {/id: {kind: identity, formats: [uuid]}}}\n",
        )
        .unwrap();
        let mut owner = policy::request_contract::RequestContracts::default();
        owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
        let source: RecordedMysqlResponse = serde_json::from_value(json!({
            "status":"resultset",
            "columns":[{"name":"payload","family":"string","sql_type":"VARCHAR"}],
            "rows":[[{"kind":"string","value":json!({"id":id}).to_string()}]]
        }))
        .unwrap();
        let (response, pending) = materialize_response(
            &source,
            Default::default(),
            Some("SELECT payload FROM tasks"),
            Some("app"),
            Some((&owner, "case")),
        )
        .unwrap();
        assert_eq!(response, source);
        assert!(!owner.has_identities("case"));
        let changed = || crate::value_contract::identities::IdentityPair {
            source: json!(id).to_string(),
            target: json!(alternate).to_string(),
        };
        assert!(owner.preview_identity_pairs("case", &[changed()]).is_ok());
        owner.commit_identity(pending.unwrap()).unwrap();
        assert!(owner.preview_identity_pairs("case", &[changed()]).is_err());
    }
}
