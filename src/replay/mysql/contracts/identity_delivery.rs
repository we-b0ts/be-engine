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
    let rules =
        owner.mysql_compiled_rules(Surface::DependencyRequest, Some(case), identity, record);
    ensure!(
        !rules.is_empty(),
        "SQL response has no proven projection or field contract"
    );
    let comparison = policy::compare_mysql_values(
        record.database.as_deref(),
        record.sql.as_deref(),
        record.params.as_deref(),
        request.sql,
        request.params,
        &rules,
        clocks,
    )?;
    ensure!(
        comparison.passed(),
        "SQL response predicate field contract failed"
    );
    owner.identity_decision(case, &comparison)?;
    Ok(record.response.clone())
}

pub(super) fn materialize_response(
    source: &RecordedMysqlResponse,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    sql: Option<&str>,
    database: Option<&str>,
    identities: Option<(&policy::request_contract::RequestContracts, &str)>,
) -> Result<RecordedMysqlResponse> {
    let mut pending: Option<crate::value_contract::identities::IdentityDecision> = None;
    let mut result = source.clone();
    let mut columns = BTreeMap::<usize, Vec<&CompiledRule>>::new();
    for rule in rules {
        let indices = match &rule.rule.slot {
            Slot::SqlColumn(column) => {
                // An independently proven projection can omit a Source column.
                if !source
                    .columns
                    .iter()
                    .any(|c| c.column.as_deref().unwrap_or(&c.name) == column)
                {
                    continue;
                }
                vec![column_index(source, column)?]
            }
            Slot::SqlField(_) => fields::response_indices(source, rule, sql, database)?,
            _ => anyhow::bail!("SQL response requires a column or physical field"),
        };
        for index in indices {
            columns.entry(index).or_default().push(rule);
        }
    }
    for (index, rules) in columns {
        for row in &mut result.rows {
            let value = row.get_mut(index).context("SQL row is incomplete")?;
            let Some(bytes) = fields::value_bytes(value, &rules[0].rule.codec)? else {
                continue;
            };
            let codec = crate::value_contract::encoded::prepared_codec(&rules)?;
            let decoded = codec.decode(&bytes)?;
            let mut logical =
                crate::value_contract::delivery::materialize(&decoded.logical, &rules, clocks)?;
            let mut allowed = rules
                .iter()
                .flat_map(|rule| rule.delivery_time.keys().cloned())
                .collect::<Vec<_>>();
            if let Some((owner, case)) = identities {
                let (decision, paths) = owner.translate_identity_logical(
                    case,
                    &decoded.logical,
                    &mut logical,
                    &rules,
                )?;
                allowed.extend(paths);
                if let Some(pending) = &mut pending {
                    pending.merge(decision)?;
                } else {
                    pending = Some(decision);
                }
            }
            let changed = decoded.encode(&logical, &allowed)?;
            if changed == bytes {
                continue;
            }
            if rules[0].rule.codec == crate::policy::Codec::Scalar {
                let logical = crate::json_value::parse(&changed)
                    .context("SQL scalar delivery is invalid JSON")?;
                if value.raw.is_some() {
                    let native = if let Some(text) = logical.as_str() {
                        text.to_owned()
                    } else {
                        logical.to_string()
                    };
                    value.raw = Some(ReplayBodyCapture {
                        encoding: "utf8".into(),
                        data: native,
                    });
                }
                value.value = Some(logical);
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
    // Reserve every delivered input together before publishing any bytes. A
    // failed render never changes mappings; a failed wire keeps conservative anchors.
    if let (Some((owner, _)), Some(pending)) = (identities, pending) {
        owner.commit_identity(pending)?;
    }
    Ok(result)
}
