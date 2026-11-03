//! Recognize bounded row-lock SELECTs without session-persistent side effects.
use sqlparser::{
    ast::{Expr, SetExpr, Statement, visit_expressions},
    dialect::MySqlDialect,
    parser::Parser,
};
use std::ops::ControlFlow;

pub(super) fn transaction_local(sql: &str) -> bool {
    if sql.len() > 1024 * 1024 {
        return false;
    }
    let Some(tokens) = crate::mysql::sql::tokens(sql).filter(|tokens| tokens.len() <= 64 * 1024)
    else {
        return false;
    };
    if crate::replay::mysql::optional_session::read::has_session_effect(&tokens) {
        return false;
    }
    let Ok(statements) = Parser::new(&MySqlDialect {})
        .with_recursion_limit(64)
        .try_with_sql(sql)
        .and_then(|mut parser| parser.parse_statements())
    else {
        return false;
    };
    let [Statement::Query(query)] = statements.as_slice() else {
        return false;
    };
    let SetExpr::Select(select) = query.body.as_ref() else {
        return false;
    };
    if query.locks.is_empty()
        || query.with.is_some()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
        || select.into.is_some()
    {
        return false;
    }
    // Nested queries retain the conservative native session boundary until a
    // separate complete effect proof covers them; no function whitelist is added.
    visit_expressions(query, |expr| match expr {
        Expr::Subquery(_) | Expr::Exists { .. } | Expr::InSubquery { .. } => ControlFlow::Break(()),
        _ => ControlFlow::Continue(()),
    })
    .is_continue()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_locks_are_transaction_local_but_persistent_or_unknown_effects_are_not() {
        for sql in [
            "SELECT users.id, users.name FROM users WHERE users.id=7 FOR UPDATE",
            "SELECT id FROM users WHERE id=? LIMIT 1 FOR SHARE",
        ] {
            assert!(transaction_local(sql), "{sql}");
        }
        for sql in [
            // This parser does not support the legacy lock syntax. Retain the
            // conservative setup boundary rather than guessing an AST proof.
            "SELECT id FROM users WHERE id=7 LOCK IN SHARE MODE",
            "SELECT id FROM users WHERE id=7",
            "SELECT @session_value FROM users FOR UPDATE",
            "SELECT GET_LOCK('name',0) FROM users FOR UPDATE",
            "SELECT RELEASE_LOCK('name') FROM users FOR UPDATE",
            "SELECT id INTO @session_value FROM users FOR UPDATE",
            "SELECT id INTO OUTFILE '/tmp/output' FROM users FOR UPDATE",
            "SELECT (SELECT id FROM users) FROM users FOR UPDATE",
            "WITH selected AS (SELECT id FROM users) SELECT id FROM selected FOR UPDATE",
            "SET @session_value=7",
            "UPDATE users SET active=1 WHERE id=7",
            "SELECT id FROM users FOR UPDATE; COMMIT",
        ] {
            assert!(!transaction_local(sql), "{sql}");
        }
    }
}
