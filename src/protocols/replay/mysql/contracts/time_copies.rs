//! Retain selected Source time leaves until their real response is delivered.
use super::*;
use crate::mysql::sql::{
    bounds,
    field_bindings::{self, FieldIdentity},
};
use crate::value_contract::time_copies::{self, TimeCopyLeaf};
use sha2::{Digest, Sha256};
use traffic_contract::provenance::ValueOrigin;
pub(crate) mod global;

type Recorder<'a> = dyn FnMut(
        ValueOrigin,
        ValueOrigin,
        &str,
        &str,
        &Value,
        &Value,
        &crate::policy::TimeContract,
    ) -> Result<()>
    + 'a;

#[derive(Debug, Clone)]
struct Column {
    index: usize,
    origin: FieldIdentity,
    codec: crate::policy::Codec,
    rows: Vec<Row>,
}

#[derive(Debug, Clone)]
struct Row {
    index: usize,
    digest: [u8; 32],
    leaves: Vec<TimeCopyLeaf>,
}
#[derive(Debug, Clone)]
pub(crate) struct PreparedRead {
    host: String,
    port: u16,
    columns: Vec<Column>,
    row_count: usize,
}

fn analysis(
    response: &RecordedMysqlResponse,
    sql: Option<&str>,
    database: Option<&str>,
) -> Option<Arc<field_bindings::FieldAnalysis>> {
    response
        .columns
        .iter()
        .any(|column| {
            column.database.is_none() || column.table.is_none() || column.column.is_none()
        })
        .then(|| {
            sql.and_then(bounds::statement)
                .and_then(|tokens| field_bindings::analyze(&tokens, database))
        })
        .flatten()
}

impl PreparedRead {
    fn observe_delivered(
        &self,
        identity: &ReplaySessionIdentity,
        delivered: &RecordedMysqlResponse,
        delivered_sql: Option<&str>,
        record: &mut Recorder<'_>,
    ) -> Result<usize> {
        if delivered.status != "resultset" || delivered.rows_truncated {
            return Ok(0);
        }
        ensure!(
            delivered.rows.len() == self.row_count,
            "SQL time-copy delivery changed row inventory"
        );
        let endpoint = identity
            .target
            .as_ref()
            .context("SQL time-copy delivery lacks actual endpoint")?;
        let target_analysis = analysis(delivered, delivered_sql, identity.database.as_deref());
        let mut recorded = 0;
        for column in &self.columns {
            let Some(target_origin) =
                fields::response_origin(delivered, column.index, target_analysis.as_deref())
            else {
                continue;
            };
            if target_origin != column.origin {
                continue;
            }
            let (Some(source_database), Some(target_database)) = (
                column.origin.database.as_deref(),
                target_origin.database.as_deref(),
            ) else {
                continue;
            };
            let mut leaf_pair = |source: &TimeCopyLeaf, target: &TimeCopyLeaf| -> Result<()> {
                record(
                    traffic_protocol_mysql::value_rules::ValuePosition {
                        host: &self.host,
                        port: self.port,
                        database: source_database,
                        table: &column.origin.table,
                        column: &column.origin.column,
                    }
                    .origin(),
                    traffic_protocol_mysql::value_rules::ValuePosition {
                        host: &endpoint.host,
                        port: endpoint.port,
                        database: target_database,
                        table: &target_origin.table,
                        column: &target_origin.column,
                    }
                    .origin(),
                    &source.pattern,
                    &target.pattern,
                    &source.value,
                    &target.value,
                    &source.time,
                )?;
                recorded += 1;
                Ok(())
            };
            for row in &column.rows {
                let value = delivered
                    .rows
                    .get(row.index)
                    .and_then(|row| row.get(column.index))
                    .context("SQL time-copy delivered row is incomplete")?;
                let Some(bytes) = fields::value_bytes(value, &column.codec)? else {
                    continue;
                };
                if <[u8; 32]>::from(Sha256::digest(&bytes)) == row.digest {
                    // Ordinary historical reads reuse their original parsed leaves.
                    for leaf in &row.leaves {
                        leaf_pair(leaf, leaf)?;
                    }
                    continue;
                }
                let decoded = crate::value_codec::CodecView::decode(&column.codec, &bytes)?;
                let target_leaves = row
                    .leaves
                    .iter()
                    .filter_map(|leaf| {
                        decoded
                            .logical
                            .pointer(&leaf.pointer)
                            .map(|value| (leaf, value))
                    })
                    .map(|(leaf, value)| {
                        crate::value_contract::json::parse_time_pair(value, value, &leaf.time)?;
                        Ok(TimeCopyLeaf {
                            value: value.clone(),
                            ..leaf.clone()
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let targets = target_leaves
                    .iter()
                    .map(|leaf| ((leaf.pattern.as_str(), leaf.pointer.as_str()), leaf))
                    .collect::<BTreeMap<_, _>>();
                for source in &row.leaves {
                    if let Some(target) =
                        targets.get(&(source.pattern.as_str(), source.pointer.as_str()))
                    {
                        leaf_pair(source, target)?;
                    }
                }
            }
        }
        Ok(recorded)
    }
}
