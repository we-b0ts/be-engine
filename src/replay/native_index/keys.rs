use super::ReplaySource;

/// Startup and Process share matching permissions; their real ownership remains
/// on each exchange and is checked independently for startup/lane admission.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::replay) enum ScopePartition {
    Case(Option<String>),
    Run,
    Shared,
}

impl ScopePartition {
    pub(in crate::replay) fn new(source: ReplaySource, case: Option<&str>) -> Self {
        if source.is_run_owned() {
            Self::Run
        } else {
            Self::Case(case.map(str::to_owned))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::replay) struct HttpKey {
    pub scope: ScopePartition,
    pub secure: bool,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::replay) struct RedisKey {
    pub scope: ScopePartition,
    pub host: String,
    pub port: u16,
    pub resp_version: u8,
    pub database: i64,
    pub username: Option<String>,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::replay) enum MysqlCommand {
    Any,
    Sql,
    Other(String),
}

impl MysqlCommand {
    pub(in crate::replay) fn new(command: Option<&str>) -> Self {
        match command {
            None => Self::Any,
            Some("COM_QUERY" | "COM_STMT_EXECUTE") => Self::Sql,
            Some(command) => Self::Other(command.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::replay) struct MysqlKey {
    pub scope: ScopePartition,
    pub host: String,
    pub port: u16,
    pub database: Option<String>,
    pub username: Option<String>,
    pub command: MysqlCommand,
}
