//! Source-driven MySQL payload and native temporal inference.
use super::*;
use crate::mysql::sql::field_bindings::FieldIdentity;
use crate::policy::{CompiledPolicy, FieldContract};
use crate::value_contract::json::{self, Field};

pub(crate) const MYSQL_ID: &str = "global.mysql";
mod delivery;
mod witness;
pub(super) use delivery::{translate_selection, write_value};
pub(in crate::replay) use witness::validate_source_record;
pub(crate) use witness::validate_witness_with_time_copies;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Temporal {
    Date,
    Datetime,
}

type Origin = (String, u16, String, String, String);

#[derive(Debug, Clone, Default)]
pub(crate) struct Metadata {
    types: Arc<BTreeMap<Origin, Option<Temporal>>>,
}

impl Metadata {
    pub(crate) fn observe_event(&mut self, event: &Value) -> Result<()> {
        if event["event_type"] != "mysql_exchange" {
            return Ok(());
        }
        let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
        if let Some(source) = crate::replay::identity_from_exchange(&record) {
            self.observe(
                &ReplaySessionIdentity {
                    target: Some(source.target),
                    database: source.database,
                    username: source.username,
                },
                &record,
            );
        }
        Ok(())
    }
    pub(in crate::replay) fn observe(
        &mut self,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
    ) {
        let Some(target) = &identity.target else {
            return;
        };
        let analysis = record
            .sql
            .as_deref()
            .and_then(crate::mysql::sql::bounds::statement)
            .and_then(|tokens| {
                crate::mysql::sql::field_bindings::analyze(&tokens, record.database.as_deref())
            });
        for (index, column) in record.response.columns.iter().enumerate() {
            let Some(origin) =
                fields::response_origin(&record.response, index, analysis.as_deref())
            else {
                continue;
            };
            let Some(database) = origin.database else {
                continue;
            };
            let temporal = temporal(column);
            let key = (
                target.host.to_ascii_lowercase(),
                target.port,
                database,
                origin.table,
                origin.column.to_ascii_lowercase(),
            );
            if self.types.len() >= 16384 && !self.types.contains_key(&key) {
                continue;
            }
            Arc::make_mut(&mut self.types)
                .entry(key)
                .and_modify(|prior| {
                    if *prior != temporal {
                        *prior = None;
                    }
                })
                .or_insert(temporal);
        }
    }

    fn temporal(
        &self,
        identity: &ReplaySessionIdentity,
        origin: &FieldIdentity,
    ) -> Option<Temporal> {
        let target = identity.target.as_ref()?;
        self.types
            .get(&(
                target.host.to_ascii_lowercase(),
                target.port,
                origin.database.clone()?,
                origin.table.clone(),
                origin.column.to_ascii_lowercase(),
            ))
            .copied()
            .flatten()
    }
}

fn temporal(column: &RecordedMysqlColumn) -> Option<Temporal> {
    match (column.sql_type.as_str(), column.family.as_str()) {
        ("DATE", "date") => Some(Temporal::Date),
        ("DATETIME" | "TIMESTAMP", "datetime") => Some(Temporal::Datetime),
        _ => None,
    }
}

fn native_scope(policy: &CompiledPolicy, database: Option<&str>) -> bool {
    (policy.mysql.is_some() || policy.global_json.is_some())
        && policy
            .mysql
            .as_ref()
            .is_none_or(|mysql| mysql.matches_database(database))
}

pub(in crate::replay) struct RequestContext<'a> {
    pub(in crate::replay) policy: &'a CompiledPolicy,
    pub(in crate::replay) metadata: Metadata,
    pub(in crate::replay) identity: &'a ReplaySessionIdentity,
    parameter_types: BTreeMap<usize, Temporal>,
}

pub(in crate::replay) struct Selection {
    pub(in crate::replay) source: Value,
    pub(in crate::replay) target: Value,
    pub(in crate::replay) fields: Vec<(String, FieldContract)>,
    pub(in crate::replay) id: &'static str,
    pub(in crate::replay) date: bool,
    pub(in crate::replay) inferred: bool,
}

impl RequestContext<'_> {
    pub(in crate::replay) fn select(
        &self,
        source: &crate::mysql::sql::Token,
        target: &crate::mysql::sql::Token,
        origin: Option<&FieldIdentity>,
        position: usize,
        clocks: AnchorClocks,
    ) -> Result<Option<Selection>> {
        use crate::mysql::sql::Token;
        if let Some(mysql) = &self.policy.mysql
            && let Some(origin) = origin
            && let Some(field) =
                mysql.field(origin.database.as_deref(), &origin.table, &origin.column)?
        {
            let source = native_scalar(source)?;
            let target = native_scalar(target)?;
            let contract = field.select_contract_with_clock(
                &source,
                clocks.dependency.source.or(clocks.case.source),
            )?;
            return Ok(Some(Selection {
                source,
                target,
                fields: vec![(String::new(), contract)],
                id: MYSQL_ID,
                date: false,
                inferred: false,
            }));
        }
        let database = origin
            .and_then(|origin| origin.database.as_deref())
            .or(self.identity.database.as_deref());
        if native_scope(self.policy, database) {
            if let Some(temporal) =
                origin.and_then(|origin| self.metadata.temporal(self.identity, origin))
            {
                return temporal_selection(
                    native_scalar(source)?,
                    native_scalar(target)?,
                    temporal,
                )
                .map(Some);
            }
            if let Some(temporal) = self.parameter_types.get(&position) {
                return temporal_selection(
                    native_scalar(source)?,
                    native_scalar(target)?,
                    *temporal,
                )
                .map(Some);
            }
        }
        let Some(json) = &self.policy.global_json else {
            return Ok(None);
        };
        let Token::Bytes(source) = source else {
            return Ok(None);
        };
        let Some(logical) = crate::json_value::parse(source) else {
            return Ok(None);
        };
        let Token::Bytes(target) = target else {
            anyhow::bail!("SQL JSON changed its native string representation")
        };
        let actual =
            crate::json_value::parse(target).context("Target SQL JSON cannot be decoded")?;
        Ok(Some(Selection {
            fields: json.fields_with_clocks(&logical, clocks)?,
            source: logical,
            target: actual,
            id: crate::policy::GLOBAL_JSON_ID,
            date: false,
            inferred: false,
        }))
    }
}

impl<'a> RequestContext<'a> {
    pub(in crate::replay) fn new(
        policy: &'a CompiledPolicy,
        metadata: Metadata,
        identity: &'a ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
    ) -> Self {
        let mut parameter_types = BTreeMap::new();
        if let Some(tokens) = record
            .sql
            .as_deref()
            .and_then(crate::mysql::sql::bounds::statement)
        {
            for (position, parameter) in tokens
                .iter()
                .enumerate()
                .filter(|(_, token)| **token == crate::mysql::sql::Token::Placeholder)
                .map(|(position, _)| position)
                .zip(record.params.iter().flatten())
            {
                let temporal = match parameter.kind.as_str() {
                    "date" => Some(Temporal::Date),
                    "datetime" => Some(Temporal::Datetime),
                    _ => None,
                };
                if let Some(temporal) = temporal {
                    parameter_types.insert(position, temporal);
                }
            }
        }
        Self {
            policy,
            metadata,
            identity,
            parameter_types,
        }
    }
}

fn native_scalar(token: &crate::mysql::sql::Token) -> Result<Value> {
    match token {
        crate::mysql::sql::Token::Bytes(bytes) => Ok(Value::String(
            String::from_utf8(bytes.clone()).context("SQL scalar requires UTF-8")?,
        )),
        crate::mysql::sql::Token::Number(number) => {
            crate::json_value::parse(number.as_bytes()).context("invalid SQL scalar number")
        }
        crate::mysql::sql::Token::Null => Ok(Value::Null),
        _ => anyhow::bail!("selected MySQL field is not a scalar value"),
    }
}

fn temporal_selection(source: Value, target: Value, temporal: Temporal) -> Result<Selection> {
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
        });
    }
    let contract = FieldContract::Time {
        format: crate::policy::TimestampFormat::SqlDatetime,
        relation: crate::policy::TimeRelation::PreserveOffset,
        anchor: crate::policy::TimeAnchor::DependencyRequestStart,
        // Only elapsed differences are compared. A common offset cancels;
        // this does not assert that the SQL session's local timezone is UTC.
        utc_offset: Some("+00:00".into()),
        clock_group: None,
        clock_scope: crate::policy::ClockScope::Shared,
    };
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
    })
}

pub(in crate::replay) fn compare_selection(
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
        crate::value_contract::time::compare_calendar_dates(source, target, clocks.dependency)?;
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
    Ok(json::compare(
        &selected.source,
        &selected.target,
        &fields,
        clocks,
    ))
}

pub(in crate::replay) fn time_leaves(
    selected: &Selection,
    policy: &CompiledPolicy,
    clocks: AnchorClocks,
) -> Result<Vec<crate::value_contract::time_copies::TimeCopyLeaf>> {
    use crate::value_contract::time_copies::TimeCopyLeaf;
    if selected.id == crate::policy::GLOBAL_JSON_ID {
        return policy
            .global_json
            .as_ref()
            .map(|plan| {
                crate::value_contract::time_copies::global_leaves(&selected.source, plan, clocks)
            })
            .transpose()
            .map(Option::unwrap_or_default);
    }
    if selected.date {
        return Ok(vec![TimeCopyLeaf {
            pattern: String::new(),
            pointer: String::new(),
            value: selected.source.clone(),
            time: native_date_time(),
        }]);
    }
    Ok(selected
        .fields
        .iter()
        .filter_map(|(pointer, field)| {
            field.time().and_then(|time| {
                selected.source.pointer(pointer).map(|value| TimeCopyLeaf {
                    pattern: pointer.clone(),
                    pointer: pointer.clone(),
                    value: value.clone(),
                    time,
                })
            })
        })
        .collect())
}

fn native_date_time() -> crate::policy::TimeContract {
    crate::policy::TimeContract {
        format: crate::policy::TimestampFormat::CalendarDate,
        relation: crate::policy::TimeRelation::PreserveOffset,
        anchor: crate::policy::TimeAnchor::DependencyRequestStart,
        utc_offset: Some("+00:00".into()),
        clock_group: None,
        clock_scope: crate::policy::ClockScope::Shared,
    }
}

pub(in crate::replay) fn compare_selection_with_context(
    selected: &Selection,
    clocks: AnchorClocks,
    copies: &[crate::value_contract::json::VerifiedTimeCopy],
    policy: &CompiledPolicy,
) -> Result<Comparison> {
    if selected.id == crate::policy::GLOBAL_JSON_ID
        && let Some(plan) = &policy.global_json
    {
        return crate::value_contract::global::compare_logical_with_time_copies(
            &selected.source,
            &selected.target,
            plan,
            &[],
            clocks,
            copies,
        );
    }
    compare_selection_with_copies(selected, clocks, copies)
}

pub(in crate::replay) fn compare_selection_with_copies(
    selected: &Selection,
    clocks: AnchorClocks,
    copies: &[crate::value_contract::json::VerifiedTimeCopy],
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
        let time = native_date_time();
        if copies.iter().any(|copy| {
            copy.permits_value(MYSQL_ID, "", "", &selected.source, &selected.target, &time)
        }) {
            let mut result = Comparison::default();
            result.evaluated.insert(MYSQL_ID.into());
            result.time_validations.insert(MYSQL_ID.into(), 1);
            return Ok(result);
        }
        return compare_selection(selected, clocks);
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
    Ok(json::compare_with_time_copies(
        &selected.source,
        &selected.target,
        &fields,
        clocks,
        copies,
    ))
}

fn scalar_value(value: &RecordedMysqlValue) -> Result<Value> {
    let bytes = fields::value_bytes(value, &crate::policy::Codec::Scalar)?
        .context("MySQL scalar disappeared")?;
    crate::json_value::parse(&bytes).context("MySQL scalar encoding is invalid")
}

#[allow(clippy::too_many_arguments)]
pub(super) fn response_selection(
    policy: &CompiledPolicy,
    response: &RecordedMysqlResponse,
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
    let analysis = sql
        .and_then(crate::mysql::sql::bounds::statement)
        .and_then(|tokens| crate::mysql::sql::field_bindings::analyze(&tokens, database));
    let origin = fields::response_origin(response, index, analysis.as_deref());
    if let Some(mysql) = &policy.mysql
        && let Some(origin) = &origin
        && let Some(field) =
            mysql.field(origin.database.as_deref(), &origin.table, &origin.column)?
    {
        let source = scalar_value(source)?;
        let contract = field
            .select_contract_with_clock(&source, clocks.dependency.source.or(clocks.case.source))?;
        return Ok(Some(Selection {
            source,
            target: scalar_value(target)?,
            fields: vec![(String::new(), contract)],
            id: MYSQL_ID,
            date: false,
            inferred: false,
        }));
    }
    if native_scope(
        policy,
        origin
            .as_ref()
            .and_then(|origin| origin.database.as_deref())
            .or(database),
    ) && let Some(temporal) = temporal(column)
    {
        return temporal_selection(scalar_value(source)?, scalar_value(target)?, temporal)
            .map(Some);
    }
    let Some(json) = &policy.global_json else {
        return Ok(None);
    };
    if !matches!(source.kind.as_str(), "string" | "binary" | "json") {
        return Ok(None);
    }
    let Some(bytes) = super::value_bytes(source)? else {
        return Ok(None);
    };
    let Some(source) = crate::json_value::parse(&bytes) else {
        return Ok(None);
    };
    ensure!(target.kind != "null", "MySQL JSON value changed to NULL");
    let bytes = super::value_bytes(target)?.context("MySQL JSON target disappeared")?;
    let target = crate::json_value::parse(&bytes)
        .context("Target MySQL result changed from JSON encoding")?;
    Ok(Some(Selection {
        fields: json.fields_with_clocks(&source, clocks)?,
        source,
        target,
        id: crate::policy::GLOBAL_JSON_ID,
        date: false,
        inferred: false,
    }))
}

pub(in crate::replay) fn compare_response(
    policy: &CompiledPolicy,
    source: &RecordedMysqlResponse,
    target: &RecordedMysqlResponse,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_response_inner(policy, source, target, sql, database, clocks, false)
}

pub(super) fn compare_input_response(
    policy: &CompiledPolicy,
    source: &RecordedMysqlResponse,
    target: &RecordedMysqlResponse,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_response_inner(policy, source, target, sql, database, clocks, true)
}

#[allow(clippy::too_many_arguments)]
fn compare_response_inner(
    policy: &CompiledPolicy,
    source: &RecordedMysqlResponse,
    target: &RecordedMysqlResponse,
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
                result.merge_and_validate(if formats_only {
                    compare_input_selection(&selected)?
                } else {
                    compare_selection_with_context(&selected, clocks, &[], policy)?
                });
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

fn compare_input_selection(selected: &Selection) -> Result<Comparison> {
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
    Ok(json::compare(
        &source,
        &target,
        &fields,
        AnchorClocks::default(),
    ))
}

#[cfg(test)]
mod tests;
