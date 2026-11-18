//! Native MySQL values, columns and prepared-statement state.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MysqlColumn {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    pub table: Option<String>,
    /// Delivered table label; the recording's table remains the physical origin.
    #[serde(skip)]
    pub table_alias: Option<String>,
    pub column: Option<String>,
    pub family: String,
    pub sql_type: String,
    pub unsigned: Option<bool>,
    pub bits: Option<u16>,
    pub nullable: Option<bool>,
    pub scale: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MysqlValue {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<ValueCapture>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ValueCapture {
    pub encoding: String,
    pub data: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct PreparedStatement {
    pub sql: String,
    pub param_count: usize,
    pub last_param_types: Vec<BoundParamType>,
}

#[derive(Debug, Clone)]
pub struct BoundParamType {
    pub type_code: u8,
    pub unsigned: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum ResultRowEncoding {
    Text,
    Binary,
}
