//! Native candidate identity with a caller-supplied Replay scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Command {
    Any,
    Sql,
    Other(String),
}

impl Command {
    pub fn new(command: Option<&str>) -> Self {
        match command {
            None => Self::Any,
            Some("COM_QUERY" | "COM_STMT_EXECUTE") => Self::Sql,
            Some(command) => Self::Other(command.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key<Scope> {
    pub scope: Scope,
    pub host: String,
    pub port: u16,
    pub database: Option<String>,
    pub username: Option<String>,
    pub command: Command,
}
