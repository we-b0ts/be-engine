//! Bounded query classification for optional session cleanup, independent of
//! SQL equivalence. Ordinary SELECT expressions are accepted without a function
//! or expression whitelist; common locking and side-effect forms remain strict.
use crate::mysql::sql::{self, Token};
use sqlparser::{ast::Statement, dialect::MySqlDialect, parser::Parser};

const MAX_SQL_BYTES: usize = 1024 * 1024;
const MAX_TOKENS: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Effect {
    ReadOnly,
    StateChange,
    Unknown,
}

pub(super) fn classify(sql: &str) -> Effect {
    if sql.len() > MAX_SQL_BYTES {
        return Effect::Unknown;
    }
    // The scanner bounds the input and rejects executable comments/hints.
    // It separates strings and quoted keywords from executable SQL tokens.
    // A batched read that inlines a large id set (for example a wide `IN (...)`)
    // must still be provable as read-only, or its session cleanup can never be
    // allowed. Both limits remain explicit so classification stays bounded.
    let Some((tokens, spans)) =
        sql::tokens_with_spans(sql).filter(|(tokens, _)| tokens.len() <= MAX_TOKENS)
    else {
        return Effect::Unknown;
    };
    let tokens = tokens
        .into_iter()
        .zip(spans)
        .map(|(token, span)| match token {
            Token::Word(word) if sql.as_bytes()[span.start] == b'`' => Token::Identifier(word),
            Token::Word(word) => Token::Word(word.to_ascii_lowercase()),
            other => other,
        })
        .collect::<Vec<_>>();
    let Ok(mut parser) = Parser::new(&MySqlDialect {})
        .with_recursion_limit(64)
        .try_with_sql(sql)
    else {
        return Effect::Unknown;
    };
    let Ok(statements) = parser.parse_statements() else {
        return Effect::Unknown;
    };
    if matches!(
        statements.as_slice(),
        [Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_) | Statement::Call(_)]
    ) {
        return Effect::StateChange;
    }
    let [Statement::Query(query)] = statements.as_slice() else {
        return Effect::Unknown;
    };
    if !query.locks.is_empty() || has_lock_or_write(&tokens) {
        return Effect::StateChange;
    }
    if query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
        || has_session_effect(&tokens)
    {
        return Effect::Unknown;
    }
    Effect::ReadOnly
}

fn has_lock_or_write(tokens: &[Token]) -> bool {
    // Scan the whole parsed statement, including CTEs, derived tables, scalar
    // subqueries and window expressions. No enumeration of SELECT shapes.
    [
        ["for", "update"].as_slice(),
        &["for", "share"],
        &["lock", "in", "share", "mode"],
    ]
    .iter()
    .any(|phrase| {
        tokens.windows(phrase.len()).any(|window| {
            window
                .iter()
                .zip(*phrase)
                .all(|(token, word)| token.is(word))
        })
    }) || tokens.iter().enumerate().any(|(index, token)| {
        // INTO includes OUTFILE, DUMPFILE and variable assignments. DML
        // inside a parser-supported CTE must not inherit query status.
        token.is("into")
            || (["insert", "update", "delete", "replace", "call"]
                .iter()
                .any(|word| token.is(word))
                && !tokens.get(index + 1).is_some_and(|next| next.is("(")))
    })
}

fn has_session_effect(tokens: &[Token]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        if ["@", "@@", ":=", "sql_calc_found_rows", "procedure"]
            .iter()
            .any(|word| token.is(word))
        {
            return true;
        }
        let (Token::Word(name) | Token::Identifier(name)) = token else {
            return false;
        };
        if !tokens.get(index + 1).is_some_and(|next| next.is("(")) {
            return false;
        }
        // This is a bounded exclusion list, not a proof about arbitrary stored
        // functions/UDFs. Ordinary function names do not need registration.
        [
            "get_lock",
            "release_lock",
            "release_all_locks",
            "service_get_read_locks",
            "service_get_write_locks",
            "service_release_locks",
            "sleep",
            "benchmark",
            "load_file",
            "sys_exec",
            "sys_eval",
        ]
        .iter()
        .any(|function| name.eq_ignore_ascii_case(function))
            || (name.eq_ignore_ascii_case("last_insert_id")
                && !tokens.get(index + 2).is_some_and(|next| next.is(")")))
    })
}
