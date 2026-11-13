//! Native prepared-statement response metadata and bounded reusable wire encoding.
use crate::{MysqlPacket, model::MysqlColumn, response::*};

#[derive(Debug, Clone)]
pub struct StatementMetadata {
    pub param_count: usize,
    pub columns: Vec<MysqlColumn>,
    prepare_wire: std::sync::OnceLock<Option<std::sync::Arc<EncodedPrepare>>>,
}

impl StatementMetadata {
    pub fn new(param_count: usize, columns: Vec<MysqlColumn>) -> Self {
        Self {
            param_count,
            columns,
            prepare_wire: std::sync::OnceLock::new(),
        }
    }
}

impl StatementMetadata {
    /// Reuse immutable native PREPARE metadata and patch only connection-local fields.
    pub fn encoded(&self, statement_id: u32, status_flags: u16) -> Option<Vec<u8>> {
        let encoded = self
            .prepare_wire
            .get_or_init(|| EncodedPrepare::new(self).map(std::sync::Arc::new))
            .as_ref()?;
        let mut bytes = encoded.bytes.clone();
        bytes[5..9].copy_from_slice(&statement_id.to_le_bytes());
        for &offset in &encoded.status_offsets {
            bytes[offset..offset + 2].copy_from_slice(&status_flags.to_le_bytes());
        }
        Some(bytes)
    }
}

#[derive(Debug)]
struct EncodedPrepare {
    bytes: Vec<u8>,
    status_offsets: Vec<usize>,
}

impl EncodedPrepare {
    fn new(metadata: &StatementMetadata) -> Option<Self> {
        let mut bytes = Vec::new();
        let mut status_offsets = Vec::new();
        for (index, (payload, eof)) in prepare_messages(metadata, 0, 0).enumerate() {
            let packet = MysqlPacket {
                sequence_id: (index as u8).wrapping_add(1),
                payload,
            };
            let end = bytes.len().checked_add(packet.encoded_len())?;
            if end > 64 * 1024 {
                return None;
            }
            if eof {
                status_offsets.push(end - 2);
            }
            bytes.extend(packet.to_wire_bytes());
        }
        Some(Self {
            bytes,
            status_offsets,
        })
    }
}

pub fn prepare_messages(
    metadata: &StatementMetadata,
    statement_id: u32,
    status_flags: u16,
) -> impl Iterator<Item = (Vec<u8>, bool)> + '_ {
    let head = stmt_prepare_ok_payload(
        statement_id,
        metadata.columns.len() as u16,
        metadata.param_count as u16,
    );
    let params = (0..metadata.param_count).map(|index| {
        (
            column_definition_payload(&MysqlColumn {
                database: None,
                name: format!("param_{}", index + 1),
                table: None,
                table_alias: None,
                column: None,
                family: "string".to_string(),
                sql_type: "VARCHAR".to_string(),
                unsigned: None,
                bits: None,
                nullable: Some(true),
                scale: None,
            }),
            false,
        )
    });
    let eof = || (eof_payload_with_status(status_flags), true);
    std::iter::once((head, false))
        .chain(params)
        .chain((metadata.param_count > 0).then(eof))
        .chain(
            metadata
                .columns
                .iter()
                .map(|column| (column_definition_payload(column), false)),
        )
        .chain((!metadata.columns.is_empty()).then(eof))
}
