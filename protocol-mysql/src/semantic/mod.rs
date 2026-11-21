//! MySQL semantic decoding independent of Recorder storage and Replay execution.
mod session;
pub use session::{SemanticRequest, SemanticSession};
mod model;
pub use model::*;
mod decode;
pub use decode::*;

#[derive(Debug, Clone)]
pub struct PreparedStatement {
    pub statement_id: u32,
    pub sql: String,
    pub param_count: usize,
    pub parameters: Vec<MysqlColumn>,
    pub columns: Vec<MysqlColumn>,
    pub last_param_types: Vec<BoundParamType>,
}

#[derive(Debug, Clone)]
pub struct BoundParamType {
    pub type_code: u8,
    pub unsigned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowProtocol {
    Text,
    Binary,
}
