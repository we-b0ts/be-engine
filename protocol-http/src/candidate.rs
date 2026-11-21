//! Native candidate identity with a caller-supplied Replay scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key<Scope> {
    pub scope: Scope,
    pub secure: bool,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: Option<String>,
}
