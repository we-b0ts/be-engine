//! Typed result cells expose physical locations and retain native wire metadata.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use traffic_protocol::message::{
    MessageEncoder, ProjectedMessage, ProjectedValue, ProtocolMessage,
};

use crate::{model::MysqlValue, recorded::RecordedMysqlResponse};

#[derive(Serialize, Deserialize)]
pub(super) struct ResponseMessage {
    pub response: RecordedMysqlResponse,
    pub source_status_before: Option<u16>,
}

impl ResponseMessage {
    pub(super) fn new(
        response: RecordedMysqlResponse,
        source_status_before: Option<u16>,
    ) -> Result<Self> {
        ensure!(
            matches!(response.status.as_str(), "ok" | "error" | "resultset"),
            "unsupported MySQL response status {}",
            response.status
        );
        ensure!(
            !response.rows_truncated
                && response.valid_row_widths()
                && response.wire_prefix.is_empty(),
            "MySQL response requires complete semantic rows"
        );
        ensure!(
            response.status != "resultset" || !response.columns.is_empty(),
            "MySQL resultset has no column metadata"
        );
        for value in response.rows.iter().flatten() {
            ensure!(
                value.raw.as_ref().is_none_or(|raw| !raw.truncated),
                "truncated MySQL cell"
            );
        }
        Ok(Self {
            response,
            source_status_before,
        })
    }
}

impl ProtocolMessage for ResponseMessage {
    fn project(&self) -> Result<ProjectedMessage> {
        let mut values = BTreeMap::new();
        let rows = self
            .response
            .rows
            .iter()
            .enumerate()
            .map(|(row_index, row)| {
                row.iter()
                    .enumerate()
                    .map(|(column_index, value)| {
                        let path = location(row_index, column_index);
                        values.insert(path.clone(), project_value(value)?);
                        Ok(json!({"kind":value.kind,"location":path}))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ProjectedMessage {
            structure: json!({"status":self.response.status,"columns":self.response.columns,
                "rows":rows,"affected_rows":self.response.affected_rows,
                "last_insert_id":self.response.last_insert_id,"error_code":self.response.error_code,
                "error_message":self.response.error_message}),
            values,
        })
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Selector {
            Value,
            Cell {
                row: usize,
                column: usize,
            },
            Field {
                database: Option<String>,
                table: Option<String>,
                column: String,
            },
        }
        Ok(match serde_json::from_value(selector.clone())? {
            Selector::Value => self.project()?.values.into_keys().collect(),
            Selector::Cell { row, column } => {
                ensure!(
                    self.response
                        .rows
                        .get(row)
                        .is_some_and(|values| column < values.len()),
                    "MySQL cell selector is out of range"
                );
                vec![location(row, column)]
            }
            Selector::Field {
                database,
                table,
                column,
            } => self
                .response
                .columns
                .iter()
                .enumerate()
                .filter(|(_, field)| {
                    field.column.as_ref().unwrap_or(&field.name) == &column
                        && database
                            .as_ref()
                            .is_none_or(|database| field.database.as_ref() == Some(database))
                        && table
                            .as_ref()
                            .is_none_or(|table| field.table.as_ref() == Some(table))
                })
                .flat_map(|(index, _)| {
                    (0..self.response.rows.len()).map(move |row| location(row, index))
                })
                .collect(),
        })
    }

    fn evidence(&self, selector: &Value) -> Result<Value> {
        let projection = self.project()?;
        let values = self
            .locate(selector)?
            .into_iter()
            .map(|location| {
                let capture = traffic_model::capture::capture_body(
                    &projection.values[&location].bytes,
                    usize::MAX,
                );
                json!({"location":location,"capture":capture})
            })
            .collect::<Vec<_>>();
        Ok(json!({"values":values}))
    }
}

impl MessageEncoder for ResponseMessage {
    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        let projection = self.project()?;
        ensure!(
            projection.values.keys().eq(values.keys()),
            "MySQL response value inventory changed"
        );
        let mut response = self.response.clone();
        for (row_index, row) in response.rows.iter_mut().enumerate() {
            for (column_index, value) in row.iter_mut().enumerate() {
                let path = location(row_index, column_index);
                let bytes = &values[&path];
                if bytes != &projection.values[&path].bytes {
                    if value.raw.is_some() {
                        *value = crate::values::mysql_bytes_or_utf8(bytes, true);
                    } else {
                        let logical: Value = serde_json::from_slice(bytes)?;
                        let source = value.value.as_ref().unwrap_or(&Value::Null);
                        ensure!(
                            std::mem::discriminant(source) == std::mem::discriminant(&logical),
                            "MySQL cell native type changed"
                        );
                        value.value = Some(logical);
                    }
                }
            }
        }
        Ok(serde_json::to_vec(&Self {
            response,
            source_status_before: self.source_status_before,
        })?
        .into())
    }
}

fn location(row: usize, column: usize) -> String {
    format!("/rows/{row}/{column}")
}

fn project_value(value: &MysqlValue) -> Result<ProjectedValue> {
    if value.raw.is_some() {
        Ok(ProjectedValue::bytes(crate::values::mysql_value_bytes(
            value,
        )?))
    } else {
        Ok(ProjectedValue::json(serde_json::to_vec(
            value.value.as_ref().unwrap_or(&Value::Null),
        )?))
    }
}
