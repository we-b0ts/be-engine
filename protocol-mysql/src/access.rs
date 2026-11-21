//! Adapt native commands to the shared SQL access analysis.
use crate::ClientCommand;
use traffic_protocol::connection::Operation as OperationClass;
pub use traffic_protocol_mysql_sql::access::*;

pub fn analyze_command(command: &ClientCommand, prepared_sql: Option<&str>) -> MysqlAccessAnalysis {
    match command.command_name.as_str() {
        "COM_QUERY" => command
            .query
            .as_deref()
            .map(analyze_sql)
            .unwrap_or_else(|| MysqlAccessAnalysis::from_class(OperationClass::Unknown)),
        "COM_STMT_EXECUTE" => prepared_sql
            .map(analyze_sql)
            .unwrap_or_else(|| MysqlAccessAnalysis::from_class(OperationClass::Unknown)),
        "COM_STMT_PREPARE" | "COM_STMT_CLOSE" | "COM_INIT_DB" | "COM_PING" | "COM_QUIT" => {
            MysqlAccessAnalysis::from_class(OperationClass::Session)
        }
        _ => MysqlAccessAnalysis::from_class(OperationClass::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation::MysqlWriteOperation;

    #[test]
    fn analyzes_prepared_writes() {
        let execute = ClientCommand {
            command_name: "COM_STMT_EXECUTE".to_string(),
            query: None,
        };
        let prepared = analyze_command(
            &execute,
            Some("INSERT INTO request_log(message) VALUES (?)"),
        );
        assert_eq!(
            prepared.writes[0].operation,
            Some(MysqlWriteOperation::Insert)
        );
    }
}
