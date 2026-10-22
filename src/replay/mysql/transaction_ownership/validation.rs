//! Conservative transaction boundaries and complete successful response evidence.
use super::*;
use crate::mysql::sql::Token;
use sqlparser::{ast::Statement, dialect::MySqlDialect, parser::Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Begin,
    End,
    Statement,
    Savepoint,
    Unknown,
}

#[derive(Default)]
pub(super) struct SqlKinds(HashMap<String, Kind>);

pub(super) fn member(
    record: &RecordedMysqlExchange,
    position: usize,
    count: usize,
    cache: &mut SqlKinds,
) -> bool {
    if !complete(record) {
        return false;
    }
    let before = record.server_status_before.expect("complete before status");
    let after = record
        .response
        .server_status
        .expect("complete after status");
    if before & 0x2008 != 0 || after & 0x2008 != 0 || before & 2 != after & 2 {
        return false;
    }
    if record.command == "COM_PING" {
        return position > 0
            && position + 1 < count
            && record.sql.is_none()
            && before & 0x200b == after & 0x200b
            && zero_effect(record);
    }
    if !matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE") {
        return false;
    }
    let Some(sql) = record.sql.as_deref() else {
        return false;
    };
    let kind = *cache
        .0
        .entry(sql.to_owned())
        .or_insert_with(|| classify(sql));
    if position == 0 {
        before & 0x2009 == 0
            && after & 0x2009 == 1
            && matches!(kind, Kind::Begin | Kind::Statement)
            && (kind != Kind::Begin || record.command == "COM_QUERY" && zero_effect(record))
    } else if position + 1 == count {
        before & 0x2009 == 1
            && after & 0x2009 == 0
            && kind == Kind::End
            && record.command == "COM_QUERY"
            && zero_effect(record)
    } else {
        before & 0x2009 == 1
            && after & 0x2009 == 1
            && (kind == Kind::Statement || kind == Kind::Savepoint && zero_effect(record))
    }
}

fn complete(record: &RecordedMysqlExchange) -> bool {
    let response = &record.response;
    record.connection_id.is_some()
        && record.query_sequence.is_some()
        && identity_from_exchange(record).is_some()
        && record.outcome == crate::DependencyExchangeOutcome::Response
        && record.parse_warnings.is_empty()
        && record.server_status_before.is_some()
        && response.server_status.is_some()
        && response.error_code.is_none()
        && response.error_message.is_none()
        && !response.rows_truncated
        && response.valid_row_widths()
        && match response.status.as_str() {
            "ok" => {
                response.affected_rows.is_some()
                    && response.last_insert_id.is_some()
                    && response.columns.is_empty()
                    && response.no_rows()
            }
            "resultset" => !response.columns.is_empty(),
            _ => false,
        }
}

fn zero_effect(record: &RecordedMysqlExchange) -> bool {
    record.response.status == "ok"
        && record.response.affected_rows == Some(0)
        && record.response.last_insert_id == Some(0)
        && record.params.as_ref().is_none_or(Vec::is_empty)
}

fn classify(sql: &str) -> Kind {
    if crate::mysql::savepoint::parse(sql).is_some() {
        return Kind::Savepoint;
    }
    if sql.len() > 1024 * 1024 {
        return Kind::Unknown;
    }
    let Some(tokens) = crate::mysql::sql::tokens(sql).filter(|tokens| tokens.len() <= 64 * 1024)
    else {
        return Kind::Unknown;
    };
    let words = |expected: &[&str]| {
        tokens.len() == expected.len()
            && tokens.iter().zip(expected).all(|(token, word)| {
                matches!(token, Token::Word(actual) if actual.eq_ignore_ascii_case(word))
            })
    };
    if words(&["begin"]) || words(&["start", "transaction"]) {
        return Kind::Begin;
    }
    if words(&["commit"]) || words(&["rollback"]) {
        return Kind::End;
    }
    let Ok(mut parser) = Parser::new(&MySqlDialect {})
        .with_recursion_limit(64)
        .try_with_sql(sql)
    else {
        return Kind::Unknown;
    };
    // Restrict promotion to statements which cannot implicitly end/restart a
    // transaction. DDL, session changes, CALL, XA and chained
    // ends require separate boundary semantics, even when IN_TRANS stays set.
    match parser.parse_statements().as_deref() {
        Ok(
            [
                Statement::Query(_)
                | Statement::Insert(_)
                | Statement::Update(_)
                | Statement::Delete(_),
            ],
        ) => Kind::Statement,
        _ => Kind::Unknown,
    }
}
