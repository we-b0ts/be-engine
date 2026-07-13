use crate::access_policy::OperationClass;
use crate::mysql::wire::ClientCommand;

pub(crate) fn classify_command(
    command: &ClientCommand,
    prepared_sql: Option<&str>,
) -> OperationClass {
    match command.command_name.as_str() {
        "COM_QUERY" => command
            .query
            .as_deref()
            .map(classify_sql)
            .unwrap_or(OperationClass::Unknown),
        "COM_STMT_EXECUTE" => prepared_sql
            .map(classify_sql)
            .unwrap_or(OperationClass::Unknown),
        "COM_STMT_PREPARE" | "COM_INIT_DB" | "COM_PING" | "COM_QUIT" => OperationClass::Session,
        _ => OperationClass::Unknown,
    }
}

pub(crate) fn classify_sql(sql: &str) -> OperationClass {
    let statements = tokenize_statements(sql);
    if statements.is_empty() {
        return OperationClass::Unknown;
    }

    let mut combined = OperationClass::Read;
    for statement in statements {
        match classify_statement(&statement) {
            OperationClass::Write => return OperationClass::Write,
            OperationClass::Unknown => combined = OperationClass::Unknown,
            OperationClass::Session if combined == OperationClass::Read => {
                combined = OperationClass::Session;
            }
            _ => {}
        }
    }
    combined
}

#[derive(Debug)]
struct Token {
    value: String,
    depth: usize,
}

fn classify_statement(tokens: &[Token]) -> OperationClass {
    let Some(operation) = top_level_operation(tokens) else {
        return OperationClass::Unknown;
    };
    match operation {
        "SELECT" => {
            let words = tokens
                .iter()
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
                matches!(
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
            if tokens.iter().any(|token| token.value == "TRANSACTION") {
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

fn top_level_operation(tokens: &[Token]) -> Option<&str> {
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
    let mut top_level = tokens.iter().filter(|token| token.depth == 0);
    let first = top_level.next()?.value.as_str();
    if first != "WITH" {
        return Some(first);
    }
    top_level
        .find(|token| OPERATIONS.contains(&token.value.as_str()))
        .map(|token| token.value.as_str())
}

fn contains_sequence(words: &[&str], needle: &[&str]) -> bool {
    words.windows(needle.len()).any(|window| window == needle)
}

fn tokenize_statements(sql: &str) -> Vec<Vec<Token>> {
    let bytes = sql.as_bytes();
    let mut statements = vec![Vec::new()];
    let mut depth = 0_usize;
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' | b'`' => {
                let quote = bytes[index];
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == b'\\' {
                        index = (index + 2).min(bytes.len());
                    } else if bytes[index] == quote {
                        if index + 1 < bytes.len() && bytes[index + 1] == quote {
                            index += 2;
                        } else {
                            index += 1;
                            break;
                        }
                    } else {
                        index += 1;
                    }
                }
            }
            b'#' => {
                index = skip_line(bytes, index + 1);
            }
            b'-' if bytes.get(index + 1) == Some(&b'-')
                && bytes.get(index + 2).is_none_or(u8::is_ascii_whitespace) =>
            {
                index = skip_line(bytes, index + 2);
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
            }
            b'(' => {
                depth += 1;
                index += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            b';' if depth == 0 => {
                if statements
                    .last()
                    .is_some_and(|statement| !statement.is_empty())
                {
                    statements.push(Vec::new());
                }
                index += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                statements
                    .last_mut()
                    .expect("statement exists")
                    .push(Token {
                        value: sql[start..index].to_ascii_uppercase(),
                        depth,
                    });
            }
            _ => index += 1,
        }
    }
    statements.retain(|statement| !statement.is_empty());
    statements
}

fn skip_line(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && !matches!(bytes[index], b'\r' | b'\n') {
        index += 1;
    }
    index
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
}
