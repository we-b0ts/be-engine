//! Native candidate identity with a caller-supplied Replay scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key<Scope> {
    pub scope: Scope,
    pub host: String,
    pub port: u16,
    pub resp_version: u8,
    pub database: i64,
    pub username: Option<String>,
    pub command: String,
}
