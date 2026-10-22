//! Explicit, causal identity delivery patches; recorded SQL and rows stay immutable.
use super::super::{config::fingerprint, matcher::mysql_values, sql_template::SqlValueTemplate};
use super::*;
use crate::policy::{Database, Protocol};
use crate::replay::{
    RecordedMysqlExchange, RecordedMysqlResponse, RecordedMysqlValue, ReplayBodyCapture,
    ReplaySessionIdentity,
};
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

pub(super) type CaptureClocks = BTreeMap<(String, String, String), DateTime<Utc>>;
#[derive(Default)]
pub(super) struct ReadValues {
    pub ids: BTreeSet<String>,
    pub source: Vec<crate::mysql::sql::Token>,
    pub target: Vec<crate::mysql::sql::Token>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct MysqlIdentityReadBackReport {
    pub case_id: String,
    pub rule_id: String,
    pub declaration: usize,
    pub column: String,
    pub json_pointers: BTreeSet<String>,
    pub source_connection_id: Option<uuid::Uuid>,
    pub source_query_sequence: Option<u64>,
    pub source_fingerprint: String,
    pub target_fingerprint: String,
}

#[derive(Debug, Clone)]
struct Patch {
    row: usize,
    column: String,
    pointer: String,
    source: String,
    target: String,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct MysqlIdentityDelivery {
    patches: Vec<Patch>,
    reports: Vec<MysqlIdentityReadBackReport>,
}

impl MysqlIdentityDelivery {
    pub(in crate::replay) fn render(
        &self,
        response: &RecordedMysqlResponse,
    ) -> Result<RecordedMysqlResponse> {
        let mut output = response.clone();
        let mut cells = BTreeMap::<(usize, usize), Value>::new();
        for patch in &self.patches {
            let Some(index) = column(response, &patch.column)? else {
                continue;
            };
            let key = (patch.row, index);
            if let std::collections::btree_map::Entry::Vacant(entry) = cells.entry(key) {
                let cell = response
                    .rows
                    .get(patch.row)
                    .and_then(|row| row.get(index))
                    .context("SQL identity delivery row is absent")?;
                entry.insert(json(cell)?);
            }
            let value = cells
                .get_mut(&key)
                .expect("selected SQL cell")
                .pointer_mut(&patch.pointer)
                .context("SQL identity delivery field is absent")?;
            ensure!(
                value.as_str() == Some(patch.source.as_str()),
                "SQL identity delivery field changed outside its selected identity"
            );
            *value = Value::String(patch.target.clone());
        }
        for ((row, index), value) in cells {
            let cell = &mut output.rows[row][index];
            let text = serde_json::to_string(&value)?;
            cell.value = Some(Value::String(text.clone()));
            if cell.raw.is_some() {
                cell.raw = Some(ReplayBodyCapture {
                    encoding: "utf8".into(),
                    data: text,
                });
            }
        }
        Ok(output)
    }

    pub(in crate::replay) fn commit(
        &self,
        owner: &DynamicValues,
        response: &RecordedMysqlResponse,
    ) -> Result<()> {
        let target = fingerprint(&serde_json::to_vec(response)?);
        let mut rows = owner
            .mysql_read_backs
            .lock()
            .expect("SQL identity deliveries");
        for report in &self.reports {
            let mut report = report.clone();
            report.target_fingerprint = target.clone();
            rows.push(report);
        }
        Ok(())
    }

    pub(in crate::replay) fn restore(
        &self,
        response: &RecordedMysqlResponse,
    ) -> Result<RecordedMysqlResponse> {
        let mut inverse = self.clone();
        for patch in &mut inverse.patches {
            std::mem::swap(&mut patch.source, &mut patch.target);
        }
        inverse.render(response)
    }
}

impl DynamicValues {
    pub(in crate::replay) fn observe_mysql_read_sources(
        &self,
        case: &str,
        events: &[Value],
    ) -> Result<()> {
        if self
            .native_guards
            .values()
            .all(|guard| guard.mysql_read_back.is_empty())
        {
            return Ok(());
        }
        for event in events
            .iter()
            .filter(|event| event["global_dependency_reason"].is_null())
        {
            self.observe_mysql_read_captures(case, event)?;
        }
        Ok(())
    }
    pub(super) fn mysql_read_values(
        &self,
        case: &str,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        values: (&RecordedMysqlResponse, &RecordedMysqlResponse),
    ) -> Result<ReadValues> {
        let Some(target) = &identity.target else {
            return Ok(ReadValues::default());
        };
        let database = identity.database.clone().map(Database::Name);
        let scope = scopes::ResourceContext {
            protocol: Protocol::Mysql,
            target,
            database: database.as_ref(),
            username: identity.username.as_deref(),
            operation: &record.command,
        };
        let tokens = mysql_values::materialized(record.sql.as_deref(), record.params.as_deref())
            .map_err(anyhow::Error::msg)?;
        let mut found = ReadValues::default();
        for rule in self.selected_scoped(case, scope, false) {
            let Some(guard) = self.native_guards.get(&rule.id) else {
                continue;
            };
            for read in &guard.mysql_read_back {
                let mut single = guard.clone();
                single.references = vec![read.resource.clone()];
                if !single.matches_reference_resource(
                    Protocol::Mysql,
                    target,
                    database.as_ref(),
                    identity.username.as_deref(),
                ) {
                    continue;
                }
                let template = SqlValueTemplate::new(
                    &read.sql,
                    &read.tables,
                    &read.table_patterns,
                    read.table_series.as_ref(),
                )?;
                if template
                    .bind(&tokens)
                    .and_then(|bound| super::super::sql_template::extract(&bound, &tokens))
                    .is_some()
                {
                    found.ids.insert(rule.id.clone());
                    found.source.extend(selected_values(values.0, read, rule)?);
                    found.target.extend(selected_values(values.1, read, rule)?);
                }
            }
        }
        Ok(found)
    }

    pub(super) fn observe_mysql_read_captures(&self, case: &str, event: &Value) -> Result<()> {
        if event["outcome"]
            .as_str()
            .is_some_and(|outcome| outcome != "response")
            || event["response_kind"] == "error"
            || event["response"]["status"] == "error"
        {
            return Ok(());
        }
        for rule in self.rules.iter().filter(|rule| {
            self.matches_case(rule, case)
                && self.native_source_allowed(rule, event)
                && self
                    .native_guards
                    .get(&rule.id)
                    .is_some_and(|guard| !guard.mysql_read_back.is_empty())
        }) {
            let value = match &rule.capture {
                DynamicValueCapture::Mysql {
                    target,
                    database,
                    value_index,
                    json_pointer,
                    ..
                } => {
                    if event["event_type"] != "mysql_exchange"
                        || event["target_host"]
                            .as_str()
                            .is_none_or(|host| !host.eq_ignore_ascii_case(&target.host))
                        || event["target_port"] != target.port
                        || event["database"] != *database
                    {
                        continue;
                    }
                    let params: Option<Vec<RecordedMysqlValue>> = serde_json::from_value(
                        event.get("params").cloned().unwrap_or(Value::Null),
                    )?;
                    let Ok(values) = mysql_values::template_values(
                        &rule.capture.mysql_template()?,
                        event["sql"].as_str(),
                        params.as_deref(),
                    ) else {
                        continue;
                    };
                    mysql::capture(
                        values
                            .get(*value_index)
                            .context("SQL capture slot absent")?,
                        json_pointer.as_deref(),
                    )?
                }
                _ => {
                    let Some(capture) = source::from_event(&rule.capture, rule.value_type, event)?
                    else {
                        continue;
                    };
                    capture.value
                }
            };
            let clock: DateTime<Utc> = event["timestamp"]
                .as_str()
                .context("SQL read-back identity capture requires a Source completion clock")?
                .parse()?;
            self.mysql_capture_clocks
                .lock()
                .expect("SQL capture clocks")
                .entry((case.into(), rule.id.clone(), value))
                .and_modify(|previous| *previous = (*previous).min(clock))
                .or_insert(clock);
        }
        Ok(())
    }

    pub(in crate::replay) fn prepare_mysql_identity_delivery(
        &self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        delivered: &RecordedMysqlResponse,
    ) -> Result<Option<MysqlIdentityDelivery>> {
        let Some(case) = case else { return Ok(None) };
        let Some(target) = &identity.target else {
            return Ok(None);
        };
        if record.outcome != crate::DependencyExchangeOutcome::Response
            || record.response.status != "resultset"
            || !matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        {
            return Ok(None);
        }
        let database = identity.database.clone().map(Database::Name);
        let scope = scopes::ResourceContext {
            protocol: Protocol::Mysql,
            target,
            database: database.as_ref(),
            username: identity.username.as_deref(),
            operation: &record.command,
        };
        let selected = self
            .selected_scoped(case, scope, false)
            .into_iter()
            .filter(|rule| {
                self.native_guards
                    .get(&rule.id)
                    .is_some_and(|guard| !guard.mysql_read_back.is_empty())
            })
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Ok(None);
        }
        let bindings = self.bindings.lock().expect("SQL read-back bindings");
        let clocks = self
            .mysql_capture_clocks
            .lock()
            .expect("SQL capture clocks");
        let mut prepared = MysqlIdentityDelivery {
            patches: vec![],
            reports: vec![],
        };
        let materialized =
            mysql_values::materialized(record.sql.as_deref(), record.params.as_deref())
                .map_err(anyhow::Error::msg)?;
        for rule in selected {
            let Some(guard) = self.native_guards.get(&rule.id) else {
                continue;
            };
            for (declaration, read) in guard.mysql_read_back.iter().enumerate() {
                let mut read_guard = guard.clone();
                read_guard.references = vec![read.resource.clone()];
                if !read_guard.matches_reference_resource(
                    Protocol::Mysql,
                    target,
                    database.as_ref(),
                    identity.username.as_deref(),
                ) {
                    continue;
                }
                let template = SqlValueTemplate::new(
                    &read.sql,
                    &read.tables,
                    &read.table_patterns,
                    read.table_series.as_ref(),
                )?;
                if template
                    .bind(&materialized)
                    .and_then(|bound| super::super::sql_template::extract(&bound, &materialized))
                    .is_none()
                {
                    continue;
                }
                ensure!(
                    !record.response.rows_truncated && record.parse_warnings.is_empty(),
                    "SQL identity read_back requires complete immutable Source rows"
                );
                let started = crate::replay::mysql::contracts::source_started(record)
                    .context("SQL identity read_back requires a Source request clock")?;
                let pairs = bindings
                    .get(case)
                    .and_then(|rules| rules.get(&rule.id))
                    .into_iter()
                    .flatten()
                    .filter(|pair| {
                        clocks
                            .get(&(case.into(), rule.id.clone(), pair.source.clone()))
                            .is_some_and(|clock| *clock <= started)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                column(&record.response, &read.column)?
                    .context("SQL identity read_back physical column is absent")?;
                ensure!(
                    record
                        .response
                        .rows
                        .iter()
                        .all(|row| row.len() == record.response.columns.len()),
                    "SQL identity read_back Source row is incomplete"
                );
                let Some(index) = column(delivered, &read.column)? else {
                    continue;
                };
                let mut hits = BTreeSet::new();
                for (row_index, row) in delivered.rows.iter().enumerate() {
                    ensure!(
                        row.len() == delivered.columns.len(),
                        "SQL identity read_back Source row is incomplete"
                    );
                    if row[index].kind == "null" {
                        continue;
                    }
                    let root = json(&row[index])?;
                    for pointer in &read.json_pointers {
                        let mut leaves = vec![];
                        select(
                            &root,
                            &pointer.split('/').skip(1).collect::<Vec<_>>(),
                            String::new(),
                            &mut leaves,
                        )?;
                        for (path, text) in leaves {
                            if !active(rule, &root, &path)? {
                                continue;
                            }
                            let template = read
                                .templates
                                .get(pointer)
                                .map(String::as_str)
                                .unwrap_or("{value}");
                            let (prefix, suffix) = template
                                .split_once("{value}")
                                .context("SQL read-back identity template is invalid")?;
                            let value = text
                                .strip_prefix(prefix)
                                .and_then(|value| value.strip_suffix(suffix));
                            let Some(pair) = pairs
                                .iter()
                                .find(|pair| value == Some(pair.source.as_str()))
                            else {
                                continue;
                            };
                            hits.insert(pointer.clone());
                            let translated = format!("{prefix}{}{suffix}", pair.target);
                            if translated != text {
                                prepared.patches.push(Patch {
                                    row: row_index,
                                    column: read.column.clone(),
                                    pointer: path,
                                    source: text,
                                    target: translated,
                                });
                            }
                        }
                    }
                }
                if !hits.is_empty() {
                    prepared.reports.push(MysqlIdentityReadBackReport {
                        case_id: case.into(),
                        rule_id: rule.id.clone(),
                        declaration,
                        column: read.column.clone(),
                        json_pointers: hits,
                        source_connection_id: record.connection_id,
                        source_query_sequence: record.query_sequence,
                        source_fingerprint: fingerprint(&serde_json::to_vec(&record.response)?),
                        target_fingerprint: String::new(),
                    });
                }
            }
        }
        Ok((!prepared.reports.is_empty()).then_some(prepared))
    }

    pub(in crate::replay) fn mysql_read_back_report(&self) -> Vec<MysqlIdentityReadBackReport> {
        self.mysql_read_backs
            .lock()
            .expect("SQL identity deliveries")
            .clone()
    }
}

fn column(response: &RecordedMysqlResponse, name: &str) -> Result<Option<usize>> {
    let indexes = response
        .columns
        .iter()
        .enumerate()
        .filter(|(_, column)| column.column.as_deref().unwrap_or(&column.name) == name)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(
        indexes.len() <= 1,
        "SQL identity read_back column is ambiguous"
    );
    Ok(indexes.first().copied())
}

fn json(cell: &RecordedMysqlValue) -> Result<Value> {
    let bytes = crate::replay::mysql_value_bytes(cell)?;
    crate::json_value::parse_with_limit(&bytes, crate::mysql::sql::bounds::MAX_STATEMENT_BYTES)
        .context("SQL identity read_back requires complete JSON with unique members")
}

fn selected_values(
    response: &RecordedMysqlResponse,
    read: &crate::policy::native::MysqlIdentityReadBack,
    rule: &DynamicValueRule,
) -> Result<Vec<crate::mysql::sql::Token>> {
    let Some(index) = column(response, &read.column)? else {
        return Ok(vec![]);
    };
    let mut values = vec![];
    for row in &response.rows {
        let cell = row
            .get(index)
            .context("SQL identity read_back result row is incomplete")?;
        if cell.kind == "null" {
            continue;
        }
        let root = json(cell)?;
        for pointer in &read.json_pointers {
            let mut leaves = vec![];
            select(
                &root,
                &pointer.split('/').skip(1).collect::<Vec<_>>(),
                String::new(),
                &mut leaves,
            )?;
            for (path, value) in leaves {
                if active(rule, &root, &path)? {
                    values.push(crate::mysql::sql::Token::Bytes(value.into_bytes()));
                }
            }
        }
    }
    Ok(values)
}

fn active(rule: &DynamicValueRule, root: &Value, pointer: &str) -> Result<bool> {
    match &rule.capture {
        DynamicValueCapture::Redis {
            when: Some(when), ..
        } => when.active(root, pointer),
        _ => Ok(true),
    }
}

fn select(
    root: &Value,
    segments: &[&str],
    path: String,
    output: &mut Vec<(String, String)>,
) -> Result<()> {
    ensure!(
        path.split('/').count() <= 65,
        "SQL identity read_back JSON nesting exceeds 64"
    );
    let Some((segment, rest)) = segments.split_first() else {
        ensure!(
            root.is_string() || root.is_null(),
            "SQL identity read_back must select a string or null leaf"
        );
        if let Some(text) = root.as_str() {
            output.push((path, text.into()))
        }
        return Ok(());
    };
    if *segment == "*" {
        if let Some(values) = root.as_array() {
            for (index, value) in values.iter().enumerate() {
                select(value, rest, format!("{path}/{index}"), output)?;
            }
        }
    } else if let Some(value) = root.pointer(&format!("/{segment}")) {
        select(value, rest, format!("{path}/{segment}"), output)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
