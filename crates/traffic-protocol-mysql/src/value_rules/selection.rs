//! Native scalar representation, temporal constraints and shared comparisons.
use super::*;
pub struct Selection {
    pub source: Value,
    pub document: Option<traffic_contract::codec::DecodedDocument>,
    pub target: Value,
    pub fields: Vec<(String, FieldContract)>,
    pub id: &'static str,
    pub date: bool,
    pub inferred: bool,
    /// A native SQL scalar is rendered without a JSON string envelope.
    pub native_scalar: bool,
}

pub(super) fn equivalent_midnight(
    source: &crate::sql::Token,
    target: &crate::sql::Token,
) -> Option<Value> {
    use crate::sql::Token;
    let (Token::Bytes(source), Token::Bytes(target)) = (source, target) else {
        return None;
    };
    let (date, datetime) = match (source.len(), target.len()) {
        (10, 19..=26) => (source, target),
        (19..=26, 10) => (target, source),
        _ => return None,
    };
    if !datetime.starts_with(date) {
        return None;
    }
    let date =
        chrono::NaiveDate::parse_from_str(std::str::from_utf8(date).ok()?, "%Y-%m-%d").ok()?;
    let datetime = std::str::from_utf8(datetime).ok()?;
    let parsed = chrono::NaiveDateTime::parse_from_str(datetime, "%Y-%m-%d %H:%M:%S%.f").ok()?;
    (parsed == date.and_hms_opt(0, 0, 0)?).then(|| Value::String(datetime.to_owned()))
}

pub(super) fn native_scalar(token: &crate::sql::Token) -> Result<Value> {
    match token {
        crate::sql::Token::Bytes(bytes) => Ok(Value::String(
            String::from_utf8(bytes.clone()).context("SQL scalar requires UTF-8")?,
        )),
        crate::sql::Token::Number(number) => serde_json::from_str(number)
            .map(Value::Number)
            .context("invalid SQL scalar number"),
        crate::sql::Token::Null => Ok(Value::Null),
        _ => anyhow::bail!("selected MySQL field is not a scalar value"),
    }
}

pub(super) fn global_scalar_selection(
    plan: &dyn FormatHost,
    source: Value,
    target: Value,
    clocks: AnchorClocks,
) -> Result<Option<Selection>> {
    if !plan
        .field_plan()
        .inferred_contract(&source)
        .ok()
        .flatten()
        .is_some_and(|contract| contract.time().is_some())
    {
        return Ok(None);
    }
    let fields = plan.field_plan().fields_with_clocks(&source, clocks)?;
    if !fields.iter().any(|(_, field)| field.time().is_some()) {
        return Ok(None);
    }
    Ok(Some(Selection {
        source,
        target,
        fields,
        id: GLOBAL_JSON_ID,
        date: false,
        inferred: false,
        native_scalar: true,
        document: None,
    }))
}

/// Native types and global scalar formats describe one physical value. They
/// cannot invent a clock relationship with another column or result row.
pub(super) fn independent_scalar_contract(mut contract: FieldContract) -> Result<FieldContract> {
    if let FieldContract::Time { clock_group, .. } = &mut contract {
        let digest =
            traffic_contract::fingerprint::digest("traffic-policy/mysql-scalar-clock/v1", &())?;
        *clock_group = Some(format!("schema.{}", &digest[7..39]));
    }
    Ok(contract)
}

pub fn temporal_selection(source: Value, target: Value, temporal: Temporal) -> Result<Selection> {
    // SQL NULL is an exact native value; it is never an absent JSON leaf.
    if source.is_null() || target.is_null() {
        ensure!(source == target, "SQL temporal NULL/value presence changed");
        return Ok(Selection {
            source,
            target,
            fields: vec![],
            id: MYSQL_ID,
            date: false,
            inferred: false,
            native_scalar: true,
            document: None,
        });
    }
    let valid_source = source.as_str().is_some_and(|text| match temporal {
        Temporal::Date => chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").is_ok(),
        Temporal::Datetime => {
            chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f").is_ok()
        }
    });
    if !valid_source {
        // Zero dates and unsupported native representations retain exactness.
        return Ok(Selection {
            source,
            target,
            fields: vec![],
            id: MYSQL_ID,
            date: false,
            inferred: false,
            native_scalar: true,
            document: None,
        });
    }
    let contract = independent_scalar_contract(FieldContract::Time {
        format: traffic_contract::rule::TimestampFormat::SqlDatetime,
        relation: traffic_contract::rule::TimeRelation::PreserveOffset,
        anchor: traffic_contract::rule::TimeAnchor::DependencyRequestStart,
        // Only elapsed differences are compared. A common offset cancels;
        // this does not assert that the SQL session's local timezone is UTC.
        utc_offset: Some("+00:00".into()),
        clock_group: None,
        clock_scope: traffic_contract::rule::ClockScope::Shared,
    })?;
    Ok(Selection {
        source,
        target,
        fields: if temporal == Temporal::Datetime {
            vec![(String::new(), contract)]
        } else {
            vec![]
        },
        id: MYSQL_ID,
        date: temporal == Temporal::Date,
        inferred: true,
        native_scalar: true,
        document: None,
    })
}

pub fn compare_selection(
    context: &ExecutionContext<'_>,
    selected: &Selection,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    if selected.source == selected.target
        && selected.id == MYSQL_ID
        && (selected.date
            || selected
                .fields
                .iter()
                .all(|(_, field)| field.time().is_some()))
    {
        let mut result = Comparison::default();
        if selected.date || !selected.fields.is_empty() {
            result.evaluated.insert(MYSQL_ID.into());
        }
        return Ok(result);
    }
    if selected.date {
        let source = chrono::NaiveDate::parse_from_str(
            selected
                .source
                .as_str()
                .context("SQL DATE requires a string")?,
            "%Y-%m-%d",
        )?;
        let target = chrono::NaiveDate::parse_from_str(
            selected
                .target
                .as_str()
                .context("SQL DATE requires a string")?,
            "%Y-%m-%d",
        )?;
        traffic_contract::time::compare_calendar_dates(source, target, clocks.dependency)?;
        let mut result = Comparison::default();
        result.evaluated.insert(MYSQL_ID.into());
        result.time_validations.insert(MYSQL_ID.into(), 1);
        return Ok(result);
    }
    let fields = selected
        .fields
        .iter()
        .map(|(pointer, contract)| Field {
            rule_id: selected.id,
            pointer,
            contract,
        })
        .collect::<Vec<_>>();
    Ok(json::compare_all(
        &selected.source,
        &selected.target,
        &fields,
        &[],
        &[],
        clocks,
        &[],
        context.metadata,
    ))
}
