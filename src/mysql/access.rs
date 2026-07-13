use crate::access_policy::OperationClass;
use crate::mysql::operation::MysqlWriteOperation;
use crate::mysql::wire::ClientCommand;

mod lexer;

use lexer::{Token, TokenKind, tokenize_statements};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MysqlAccessAnalysis {
    pub(crate) class: OperationClass,
    pub(crate) writes: Vec<MysqlWrite>,
    pub(crate) statements_complete: bool,
}

impl MysqlAccessAnalysis {
    fn from_class(class: OperationClass) -> Self {
        Self {
            class,
            writes: Vec::new(),
            statements_complete: class != OperationClass::Unknown,
        }
    }

    pub(crate) fn operation_names(&self) -> Vec<String> {
        let mut operations = Vec::new();
        for write in &self.writes {
            if let Some(operation) = write.operation {
                let operation = operation.as_str().to_string();
                if !operations.contains(&operation) {
                    operations.push(operation);
                }
            }
        }
        operations
    }

    pub(crate) fn resource_names(&self, default_database: Option<&str>) -> Vec<String> {
        let mut resources = Vec::new();
        for write in &self.writes {
            for table in &write.tables {
                let database = table.database.as_deref().or(default_database);
                let resource = database
                    .map(|database| format!("{database}.{}", table.table))
                    .unwrap_or_else(|| table.table.clone());
                if !resources.contains(&resource) {
                    resources.push(resource);
                }
            }
        }
        resources
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MysqlWrite {
    pub(crate) operation: Option<MysqlWriteOperation>,
    pub(crate) tables: Vec<MysqlTableRef>,
    pub(crate) complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MysqlTableRef {
    pub(crate) database: Option<String>,
    pub(crate) table: String,
}

pub(crate) fn analyze_command(
    command: &ClientCommand,
    prepared_sql: Option<&str>,
) -> MysqlAccessAnalysis {
    match command.command_name.as_str() {
        "COM_QUERY" => command
            .query
            .as_deref()
            .map(analyze_sql)
            .unwrap_or_else(|| MysqlAccessAnalysis::from_class(OperationClass::Unknown)),
        "COM_STMT_EXECUTE" => prepared_sql
            .map(analyze_sql)
            .unwrap_or_else(|| MysqlAccessAnalysis::from_class(OperationClass::Unknown)),
        "COM_STMT_PREPARE" | "COM_INIT_DB" | "COM_PING" | "COM_QUIT" => {
            MysqlAccessAnalysis::from_class(OperationClass::Session)
        }
        _ => MysqlAccessAnalysis::from_class(OperationClass::Unknown),
    }
}

#[cfg(test)]
pub(crate) fn classify_sql(sql: &str) -> OperationClass {
    analyze_sql(sql).class
}

pub(crate) fn analyze_sql(sql: &str) -> MysqlAccessAnalysis {
    let statements = tokenize_statements(sql);
    if statements.is_empty() {
        return MysqlAccessAnalysis::from_class(OperationClass::Unknown);
    }

    let mut combined = OperationClass::Read;
    let mut writes = Vec::new();
    let mut statements_complete = true;
    let mut has_session_statement = false;
    for statement in statements {
        let class = classify_statement(&statement);
        match class {
            OperationClass::Write => {
                combined = OperationClass::Write;
                writes.push(analyze_write(&statement));
            }
            OperationClass::Unknown if combined != OperationClass::Write => {
                combined = OperationClass::Unknown;
                statements_complete = false;
            }
            OperationClass::Unknown => statements_complete = false,
            OperationClass::Session if combined == OperationClass::Read => {
                combined = OperationClass::Session;
                has_session_statement = true;
            }
            OperationClass::Session => has_session_statement = true,
            _ => {}
        }
    }
    if combined == OperationClass::Write && has_session_statement {
        statements_complete = false;
    }
    MysqlAccessAnalysis {
        class: combined,
        writes,
        statements_complete,
    }
}

fn classify_statement(tokens: &[Token]) -> OperationClass {
    let Some((_, operation)) = top_level_operation(tokens) else {
        return OperationClass::Unknown;
    };
    match operation {
        "SELECT" => {
            let words = tokens
                .iter()
                .filter(|token| token.kind == TokenKind::Word)
                .map(|token| token.value.as_str())
                .collect::<Vec<_>>();
            if contains_sequence(&words, &["FOR", "UPDATE"])
                || contains_sequence(&words, &["LOCK", "IN", "SHARE", "MODE"])
                || contains_sequence(&words, &["INTO", "OUTFILE"])
                || contains_sequence(&words, &["INTO", "DUMPFILE"])
            {
                OperationClass::Write
            } else {
                OperationClass::Read
            }
        }
        "SHOW" | "DESC" | "DESCRIBE" | "EXPLAIN" | "VALUES" | "TABLE" => OperationClass::Read,
        "SET" => {
            if tokens.iter().any(|token| {
                token.kind == TokenKind::Word
                    && matches!(
                        token.value.as_str(),
                        "GLOBAL" | "PERSIST" | "PERSIST_ONLY" | "PASSWORD"
                    )
            }) {
                OperationClass::Write
            } else {
                OperationClass::Session
            }
        }
        "USE" | "BEGIN" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" => {
            OperationClass::Session
        }
        "START" => {
            if tokens
                .iter()
                .any(|token| token.kind == TokenKind::Word && token.value == "TRANSACTION")
            {
                OperationClass::Session
            } else {
                OperationClass::Write
            }
        }
        "INSERT" | "UPDATE" | "DELETE" | "REPLACE" | "CREATE" | "ALTER" | "DROP" | "TRUNCATE"
        | "RENAME" | "GRANT" | "REVOKE" | "LOAD" | "CALL" | "DO" | "HANDLER" | "LOCK"
        | "UNLOCK" | "ANALYZE" | "OPTIMIZE" | "REPAIR" | "INSTALL" | "UNINSTALL" | "FLUSH"
        | "RESET" | "KILL" | "CHANGE" => OperationClass::Write,
        _ => OperationClass::Unknown,
    }
}

fn analyze_write(tokens: &[Token]) -> MysqlWrite {
    let Some((operation_index, operation)) = top_level_operation(tokens) else {
        return incomplete_write();
    };
    match operation {
        "INSERT" => analyze_insert_like(tokens, operation_index, true),
        "REPLACE" => analyze_insert_like(tokens, operation_index, false),
        "UPDATE" => analyze_update(tokens, operation_index),
        "DELETE" => analyze_delete(tokens, operation_index),
        _ => incomplete_write(),
    }
}

fn incomplete_write() -> MysqlWrite {
    MysqlWrite {
        operation: None,
        tables: Vec::new(),
        complete: false,
    }
}

fn analyze_insert_like(tokens: &[Token], operation_index: usize, insert: bool) -> MysqlWrite {
    let mut index = operation_index + 1;
    index = skip_top_level_words(
        tokens,
        index,
        &["LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY", "IGNORE"],
    );
    if token_is_word(tokens.get(index), "INTO") {
        index += 1;
    }
    let Some((table, next)) = parse_table_ref(tokens, index) else {
        return incomplete_write();
    };
    let has_unexpected_comma = tokens
        .get(next)
        .is_some_and(|token| token.depth == 0 && token.value == ",");
    let upsert = insert
        && contains_top_level_sequence(
            tokens,
            operation_index + 1,
            &["ON", "DUPLICATE", "KEY", "UPDATE"],
        );
    MysqlWrite {
        operation: Some(if upsert {
            MysqlWriteOperation::Upsert
        } else if insert {
            MysqlWriteOperation::Insert
        } else {
            MysqlWriteOperation::Replace
        }),
        tables: vec![table],
        complete: !has_unexpected_comma,
    }
}

fn analyze_update(tokens: &[Token], operation_index: usize) -> MysqlWrite {
    let mut index = operation_index + 1;
    index = skip_top_level_words(tokens, index, &["LOW_PRIORITY", "IGNORE"]);
    let Some((table, next)) = parse_table_ref(tokens, index) else {
        return incomplete_write();
    };
    let set_index = tokens
        .iter()
        .enumerate()
        .skip(next)
        .find(|(_, token)| token.depth == 0 && token_is_word(Some(token), "SET"))
        .map(|(index, _)| index);
    let Some(set_index) = set_index else {
        return incomplete_write();
    };
    let unsafe_target_shape = tokens[next..set_index].iter().any(|token| {
        token.depth == 0
            && (token.value == "," || matches!(token.value.as_str(), "JOIN" | "STRAIGHT_JOIN"))
    });
    MysqlWrite {
        operation: Some(MysqlWriteOperation::Update),
        tables: vec![table],
        complete: !unsafe_target_shape,
    }
}

fn analyze_delete(tokens: &[Token], operation_index: usize) -> MysqlWrite {
    let mut index = operation_index + 1;
    index = skip_top_level_words(tokens, index, &["LOW_PRIORITY", "QUICK", "IGNORE"]);
    if !token_is_word(tokens.get(index), "FROM") {
        return incomplete_write();
    }
    index += 1;
    let Some((table, next)) = parse_table_ref(tokens, index) else {
        return incomplete_write();
    };
    let unsafe_target_shape = tokens[next..].iter().any(|token| {
        token.depth == 0
            && (token.value == ","
                || matches!(token.value.as_str(), "JOIN" | "STRAIGHT_JOIN" | "USING"))
    });
    MysqlWrite {
        operation: Some(MysqlWriteOperation::Delete),
        tables: vec![table],
        complete: !unsafe_target_shape,
    }
}

fn parse_table_ref(tokens: &[Token], index: usize) -> Option<(MysqlTableRef, usize)> {
    let first = identifier(tokens.get(index)?)?;
    if tokens.get(index + 1).is_some_and(|token| {
        token.depth == 0 && token.kind == TokenKind::Symbol && token.value == "."
    }) {
        let table = identifier(tokens.get(index + 2)?)?;
        return Some((
            MysqlTableRef {
                database: Some(first.to_string()),
                table: table.to_string(),
            },
            index + 3,
        ));
    }
    Some((
        MysqlTableRef {
            database: None,
            table: first.to_string(),
        },
        index + 1,
    ))
}

fn identifier(token: &Token) -> Option<&str> {
    (token.depth == 0 && matches!(token.kind, TokenKind::Word | TokenKind::QuotedIdentifier))
        .then_some(token.raw.as_str())
}

fn skip_top_level_words(tokens: &[Token], mut index: usize, words: &[&str]) -> usize {
    while tokens.get(index).is_some_and(|token| {
        token.depth == 0 && token.kind == TokenKind::Word && words.contains(&token.value.as_str())
    }) {
        index += 1;
    }
    index
}

fn token_is_word(token: Option<&Token>, value: &str) -> bool {
    token.is_some_and(|token| token.kind == TokenKind::Word && token.value == value)
}

fn top_level_operation(tokens: &[Token]) -> Option<(usize, &str)> {
    const OPERATIONS: &[&str] = &[
        "SELECT",
        "SHOW",
        "DESC",
        "DESCRIBE",
        "EXPLAIN",
        "VALUES",
        "TABLE",
        "SET",
        "USE",
        "START",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT",
        "RELEASE",
        "INSERT",
        "UPDATE",
        "DELETE",
        "REPLACE",
        "CREATE",
        "ALTER",
        "DROP",
        "TRUNCATE",
        "RENAME",
        "GRANT",
        "REVOKE",
        "LOAD",
        "CALL",
        "DO",
        "HANDLER",
        "LOCK",
        "UNLOCK",
        "ANALYZE",
        "OPTIMIZE",
        "REPAIR",
        "INSTALL",
        "UNINSTALL",
        "FLUSH",
        "RESET",
        "KILL",
        "CHANGE",
    ];
    let mut top_level = tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| token.depth == 0 && token.kind == TokenKind::Word);
    let (first_index, first) = top_level.next()?;
    if first.value != "WITH" {
        return Some((first_index, first.value.as_str()));
    }
    top_level
        .find(|(_, token)| OPERATIONS.contains(&token.value.as_str()))
        .map(|(index, token)| (index, token.value.as_str()))
}

fn contains_sequence(words: &[&str], needle: &[&str]) -> bool {
    words.windows(needle.len()).any(|window| window == needle)
}

fn contains_top_level_sequence(tokens: &[Token], start: usize, needle: &[&str]) -> bool {
    let words = tokens
        .iter()
        .skip(start)
        .filter(|token| token.depth == 0 && token.kind == TokenKind::Word)
        .map(|token| token.value.as_str())
        .collect::<Vec<_>>();
    contains_sequence(&words, needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_reads_sessions_writes_and_unknown_sql() {
        assert_eq!(classify_sql("SELECT * FROM users"), OperationClass::Read);
        assert_eq!(classify_sql("SHOW TABLES"), OperationClass::Read);
        assert_eq!(
            classify_sql("SET SESSION sql_mode = ''"),
            OperationClass::Session
        );
        assert_eq!(
            classify_sql("SET GLOBAL max_connections = 10"),
            OperationClass::Write
        );
        assert_eq!(
            classify_sql("SET PASSWORD = 'secret'"),
            OperationClass::Write
        );
        assert_eq!(classify_sql("START TRANSACTION"), OperationClass::Session);
        assert_eq!(classify_sql("START REPLICA"), OperationClass::Write);
        assert_eq!(
            classify_sql("UPDATE users SET active = 1"),
            OperationClass::Write
        );
        assert_eq!(classify_sql("XA START 'x'"), OperationClass::Unknown);
    }

    #[test]
    fn handles_comments_ctes_multi_statements_and_side_effecting_selects() {
        assert_eq!(
            classify_sql("/* read */ WITH rows AS (SELECT 1) SELECT * FROM rows"),
            OperationClass::Read
        );
        assert_eq!(
            classify_sql("WITH rows AS (SELECT 1) UPDATE users SET active = 1"),
            OperationClass::Write
        );
        assert_eq!(
            classify_sql("SELECT 1; DELETE FROM users"),
            OperationClass::Write
        );
        assert_eq!(
            classify_sql("SELECT * FROM users FOR UPDATE"),
            OperationClass::Write
        );
        assert_eq!(
            classify_sql("SELECT payload INTO OUTFILE '/tmp/out' FROM events"),
            OperationClass::Write
        );
        assert_eq!(
            classify_sql("SELECT 'DELETE FROM users'"),
            OperationClass::Read
        );
    }

    #[test]
    fn extracts_allowlist_safe_write_operations_and_tables() {
        let insert = analyze_sql("INSERT INTO pluto.request_log(message) VALUES ('ok')");
        assert_eq!(insert.writes.len(), 1);
        assert_eq!(
            insert.writes[0].operation,
            Some(MysqlWriteOperation::Insert)
        );
        assert_eq!(
            insert.writes[0].tables,
            vec![MysqlTableRef {
                database: Some("pluto".to_string()),
                table: "request_log".to_string(),
            }]
        );
        assert!(insert.writes[0].complete);

        let quoted = analyze_sql("UPDATE `pluto`.`RequestLog` SET `message` = 'ok'");
        assert_eq!(
            quoted.writes[0].operation,
            Some(MysqlWriteOperation::Update)
        );
        assert_eq!(quoted.writes[0].tables[0].table, "RequestLog");
        assert!(quoted.writes[0].complete);

        let delete = analyze_sql("DELETE QUICK FROM request_log WHERE id = 1");
        assert_eq!(
            delete.writes[0].operation,
            Some(MysqlWriteOperation::Delete)
        );
        assert!(delete.writes[0].complete);
    }

    #[test]
    fn keeps_upsert_and_unsafe_shapes_out_of_broader_operations() {
        let upsert =
            analyze_sql("INSERT INTO request_log(id) VALUES (1) ON DUPLICATE KEY UPDATE id = 1");
        assert_eq!(
            upsert.writes[0].operation,
            Some(MysqlWriteOperation::Upsert)
        );

        let multi_update = analyze_sql("UPDATE a, b SET a.value = b.value");
        assert!(!multi_update.writes[0].complete);
        let joined_delete = analyze_sql("DELETE FROM a USING a JOIN b ON a.id = b.id");
        assert!(!joined_delete.writes[0].complete);
        let locking_read = analyze_sql("SELECT * FROM request_log FOR UPDATE");
        assert_eq!(locking_read.class, OperationClass::Write);
        assert!(!locking_read.writes[0].complete);
    }

    #[test]
    fn analyzes_prepared_and_multi_statement_writes() {
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

        let multi = analyze_sql(
            "INSERT INTO request_log(message) VALUES ('a'); UPDATE request_log SET message = 'b'",
        );
        assert_eq!(multi.writes.len(), 2);
        assert_eq!(multi.class, OperationClass::Write);

        let mixed_unknown =
            analyze_sql("CUSTOM COMMAND; INSERT INTO request_log(message) VALUES ('a')");
        assert_eq!(mixed_unknown.class, OperationClass::Write);
        assert!(!mixed_unknown.statements_complete);

        let database_change =
            analyze_sql("USE other; INSERT INTO request_log(message) VALUES ('a')");
        assert_eq!(database_change.class, OperationClass::Write);
        assert!(!database_change.statements_complete);
    }
}
