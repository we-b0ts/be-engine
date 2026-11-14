//! Native semantic values and complete MySQL response observations.
use serde::Serialize;
use traffic_model::capture::BodyCapture;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MysqlWirePrefixPacket {
    pub offset_ms: u128,
    pub packet: BodyCapture,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MysqlExchangeResponse {
    /// Complete wire packets already delivered before transport termination.
    /// These are dependency evidence, never a synthesized successful resultset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wire_prefix: Vec<MysqlWirePrefixPacket>,
    /// Protocol-41 OK or final resultset EOF status, when captured completely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_status: Option<u16>,
    pub status: String,
    pub error_code: Option<u16>,
    pub error_message: Option<String>,
    pub affected_rows: Option<u64>,
    pub last_insert_id: Option<u64>,
    pub columns: Vec<MysqlColumn>,
    pub rows: Vec<Vec<MysqlValue>>,
    pub row_count: usize,
    pub rows_truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MysqlColumn {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    pub family: String,
    pub sql_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scale: Option<u8>,
    #[serde(skip_serializing)]
    pub column_type_code: u8,
    #[serde(skip_serializing)]
    pub flags: Option<u16>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MysqlValue {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<BodyCapture>,
}
