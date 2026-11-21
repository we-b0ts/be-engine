//! Project result values and retain strict unselected response envelopes.
use super::*;
fn scalar_value(value: &RecordedMysqlValue) -> Result<Value> {
    let bytes = fields::scalar_bytes(value)?.context("MySQL scalar disappeared")?;
    serde_json::from_slice(&bytes).context("MySQL scalar encoding is invalid")
}

#[allow(clippy::too_many_arguments)]
pub fn response_selection<E>(
    policy: &(impl ValuePolicy + ?Sized),
    response: &RecordedMysqlResponse<E>,
    index: usize,
    source: &RecordedMysqlValue,
    target: &RecordedMysqlValue,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
) -> Result<Option<Selection>> {
    let column = response
        .columns
        .get(index)
        .context("MySQL result column is absent")?;
    if let Some(formats) = policy.scalar_formats()
        && let Some(origin) = fields::response_origin(response, index, None).or_else(|| {
            // Native metadata already proves most result origins. Only legacy
            // columns lacking it need SQL analysis; global/native value contracts
            // do not use a physical origin at all. Avoid cloning and shaping the
            // same statement for every result cell on those ordinary paths.
            let analysis = sql
                .and_then(crate::sql::bounds::statement)
                .and_then(|tokens| crate::sql::field_bindings::analyze(&tokens, database));
            fields::response_origin(response, index, analysis.as_deref())
        })
        && let Some(field) = formats.field(&origin)?
    {
        let source = scalar_value(source)?;
        let contract = independent_scalar_contract(field.select(
            &source,
            clocks.dependency.source,
            policy.execution().metadata.policies(),
        )?)?;
        return Ok(Some(Selection {
            source,
            target: scalar_value(target)?,
            fields: vec![(String::new(), contract)],
            id: MYSQL_ID,
            date: false,
            inferred: false,
            native_scalar: true,
            document: None,
        }));
    }
    let standard_scalar_candidate = source
        .value
        .as_ref()
        .and_then(Value::as_str)
        .is_some_and(|value| (10..=35).contains(&value.len()))
        || source.raw.as_ref().is_some_and(|raw| raw.data.len() <= 48);
    if standard_scalar_candidate
        && matches!(source.kind.as_str(), "string" | "date" | "datetime")
        && let Some(json) = policy.document()
        && let Some(selected) =
            global_scalar_selection(json, scalar_value(source)?, scalar_value(target)?, clocks)?
    {
        return Ok(Some(selected));
    }
    if policy.uses_native_types()
        && let Some(temporal) = temporal(column)
    {
        return temporal_selection(scalar_value(source)?, scalar_value(target)?, temporal)
            .map(Some);
    }
    let Some(json) = policy.document() else {
        return Ok(None);
    };
    if !matches!(source.kind.as_str(), "string" | "binary" | "json") {
        return Ok(None);
    }
    let Some(bytes) = fields::encoded_bytes(source)? else {
        return Ok(None);
    };
    let Some(codec) = traffic_contract::codec::CodecPlan::try_recognize(
        &bytes,
        &serde_json::from_value(
            serde_json::json!({"protocol":"mysql", "carrier":"result_value", "native_type":source.kind}),
        )?,
        policy.execution().codecs,
    )?
    else {
        return Ok(None);
    };
    let document = codec.decode(&bytes)?;
    if matches!(document.value(), traffic_value::Value::Bytes(_)) {
        return Ok(None);
    }
    let source = &document.logical;
    let fields = json.field_plan().fields_with_clocks(source, clocks)?;
    if !source.is_object() && !source.is_array() && fields.is_empty() {
        return Ok(None);
    }
    ensure!(target.kind != "null", "MySQL content value changed to NULL");
    let bytes = fields::encoded_bytes(target)?.context("MySQL content target disappeared")?;
    let target = codec
        .decode(&bytes)
        .context("Target MySQL result violates its Source codec")?
        .logical;
    Ok(Some(Selection {
        fields,
        source: source.clone(),
        target,
        document: Some(document),
        id: GLOBAL_JSON_ID,
        date: false,
        inferred: false,
        native_scalar: false,
    }))
}

pub fn compare_response<E: Clone>(
    policy: &(impl ValuePolicy + ?Sized),
    source: &RecordedMysqlResponse<E>,
    target: &RecordedMysqlResponse<E>,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_response_inner(policy, source, target, sql, database, clocks, false)
}

/// An implicit comparison plan does not create a derived input obligation for
/// resultsets with no selected business values. The native request matcher may
/// already have proved a projection or identity without any response fields.
pub fn has_response_contracts<E>(
    policy: &(impl ValuePolicy + ?Sized),
    source: &RecordedMysqlResponse<E>,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
) -> Result<bool> {
    for row in &source.rows {
        for (index, value) in row.iter().enumerate() {
            if let Some(selected) =
                response_selection(policy, source, index, value, value, sql, database, clocks)?
                && (selected.date || !selected.fields.is_empty())
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn compare_input_response<E: Clone>(
    policy: &(impl ValuePolicy + ?Sized),
    source: &RecordedMysqlResponse<E>,
    target: &RecordedMysqlResponse<E>,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_response_inner(policy, source, target, sql, database, clocks, true)
}

#[allow(clippy::too_many_arguments)]
fn compare_response_inner<E: Clone>(
    policy: &(impl ValuePolicy + ?Sized),
    source: &RecordedMysqlResponse<E>,
    target: &RecordedMysqlResponse<E>,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
    formats_only: bool,
) -> Result<Comparison> {
    let mut remainder = source.clone();
    ensure!(
        source.columns == target.columns && source.rows.len() == target.rows.len(),
        "MySQL result metadata or row inventory changed"
    );
    let mut result = Comparison::default();
    for (row_index, (source_row, target_row)) in source.rows.iter().zip(&target.rows).enumerate() {
        ensure!(
            source_row.len() == target_row.len() && source_row.len() == source.columns.len(),
            "MySQL result row is incomplete"
        );
        for (index, (source, target)) in source_row.iter().zip(target_row).enumerate() {
            ensure!(
                source.kind == target.kind,
                "MySQL native result kind changed"
            );
            if let Some(selected) = response_selection(
                policy, &remainder, index, source, target, sql, database, clocks,
            )? {
                let mut comparison = if formats_only {
                    compare_input_selection(&policy.execution(), &selected)?
                } else {
                    compare_selection_with_context(&selected, clocks, &[], policy)?
                };
                comparison.scope_schema_clocks_in(&format!("mysql-result:{row_index}:{index}"));
                result.merge_and_validate(comparison);
                remainder.rows[row_index][index] = target.clone();
            }
        }
    }
    ensure!(
        remainder == *target,
        "unselected MySQL response value or envelope changed"
    );
    Ok(result)
}

fn compare_input_selection(
    context: &ExecutionContext<'_>,
    selected: &Selection,
) -> Result<Comparison> {
    if selected.date {
        chrono::NaiveDate::parse_from_str(
            selected
                .source
                .as_str()
                .context("Source DATE requires text")?,
            "%Y-%m-%d",
        )?;
        chrono::NaiveDate::parse_from_str(
            selected
                .target
                .as_str()
                .context("delivered DATE requires text")?,
            "%Y-%m-%d",
        )?;
        return Ok(Comparison::default());
    }
    let (mut source, mut target) = (selected.source.clone(), selected.target.clone());
    for (pointer, contract) in &selected.fields {
        if let Some(time) = contract.time() {
            let (a, b) = source
                .pointer(pointer)
                .zip(target.pointer(pointer))
                .context("delivered temporal field presence changed")?;
            json::parse_time_pair(a, b, &time)?;
            *source
                .pointer_mut(pointer)
                .context("Source time disappeared")? = Value::Null;
            *target
                .pointer_mut(pointer)
                .context("delivered time disappeared")? = Value::Null;
        }
    }
    let fields = selected
        .fields
        .iter()
        .filter(|(_, contract)| contract.time().is_none())
        .map(|(pointer, contract)| Field {
            rule_id: selected.id,
            pointer,
            contract,
        })
        .collect::<Vec<_>>();
    Ok(json::compare_all(
        &source,
        &target,
        &fields,
        &[],
        &[],
        AnchorClocks::default(),
        &[],
        context.metadata,
    ))
}
