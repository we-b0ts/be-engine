//! Native column type observations and their physical origin.
use super::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Temporal {
    Date,
    Datetime,
}

type Origin = (String, u16, String, String, String);

#[derive(Debug, Clone, Default)]
pub struct Metadata {
    types: Arc<BTreeMap<Origin, Option<Temporal>>>,
}

impl Metadata {
    pub fn observe_event(&mut self, event: &Value) -> Result<()> {
        if event["event_type"] != "mysql_exchange" {
            return Ok(());
        }
        let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
        if let Some(source) = crate::session_identity::identity_from_exchange(&record) {
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
    pub fn observe<E>(
        &mut self,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange<E>,
    ) {
        if record.response.columns.is_empty() {
            return;
        }
        let Some(target) = &identity.target else {
            return;
        };
        let analysis = record
            .sql
            .as_deref()
            .and_then(crate::sql::bounds::statement)
            .and_then(|tokens| {
                crate::sql::field_bindings::analyze(&tokens, record.database.as_deref())
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

    pub(super) fn temporal(
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

pub(super) fn temporal(column: &RecordedMysqlColumn) -> Option<Temporal> {
    match (column.sql_type.as_str(), column.family.as_str()) {
        ("DATE", "date") => Some(Temporal::Date),
        ("DATETIME" | "TIMESTAMP", "datetime") => Some(Temporal::Datetime),
        _ => None,
    }
}
