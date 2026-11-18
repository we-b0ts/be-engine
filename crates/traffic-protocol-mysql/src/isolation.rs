//! Closed transaction-isolation syntax, without treating arbitrary SET as setup.
use super::sql::{Token, tokens};

fn word(token: &Token, value: &str) -> bool {
    matches!(token, Token::Word(text) if text.eq_ignore_ascii_case(value)) || token.is(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

impl Level {
    pub fn name(self) -> &'static str {
        match self {
            Self::ReadUncommitted => "READ UNCOMMITTED",
            Self::ReadCommitted => "READ COMMITTED",
            Self::RepeatableRead => "REPEATABLE READ",
            Self::Serializable => "SERIALIZABLE",
        }
    }
    pub fn reported(value: &str) -> Option<Self> {
        if value.len() > 32 {
            return None;
        }
        match value.to_ascii_uppercase().replace('-', " ").as_str() {
            "READ UNCOMMITTED" => Some(Self::ReadUncommitted),
            "READ COMMITTED" => Some(Self::ReadCommitted),
            "REPEATABLE READ" => Some(Self::RepeatableRead),
            "SERIALIZABLE" => Some(Self::Serializable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Next,
    Session,
}

pub fn setting(sql: &str) -> Option<(Scope, Level)> {
    if sql.len() > 1024 {
        return None;
    }
    let parts = tokens(sql)?;
    let [set, rest @ ..] = parts.as_slice() else {
        return None;
    };
    if !word(set, "set") {
        return None;
    }
    let (scope, rest) = if rest.first().is_some_and(|t| word(t, "session")) {
        (Scope::Session, &rest[1..])
    } else {
        (Scope::Next, rest)
    };
    let [transaction, isolation, level, rest @ ..] = rest else {
        return None;
    };
    if !word(transaction, "transaction") || !word(isolation, "isolation") || !word(level, "level") {
        return None;
    }
    let level = match rest {
        [read, uncommitted] if word(read, "read") && word(uncommitted, "uncommitted") => {
            Level::ReadUncommitted
        }
        [read, committed] if word(read, "read") && word(committed, "committed") => {
            Level::ReadCommitted
        }
        [repeatable, read] if word(repeatable, "repeatable") && word(read, "read") => {
            Level::RepeatableRead
        }
        [serializable] if word(serializable, "serializable") => Level::Serializable,
        _ => return None,
    };
    Some((scope, level))
}

pub fn probe(sql: &str) -> bool {
    if sql.len() > 1024 {
        return false;
    }
    let Some(parts) = tokens(sql) else {
        return false;
    };
    let name = |t: &Token| word(t, "transaction_isolation") || word(t, "tx_isolation");
    match parts.as_slice() {
        [select, at, field] => select.is("select") && at.is("@@") && name(field),
        [select, at, session, dot, field] => {
            select.is("select")
                && at.is("@@")
                && session.is("session")
                && dot.is(".")
                && name(field)
        }
        _ => false,
    }
}

pub fn changes_isolation(sql: &str) -> bool {
    let prefix = sql.trim_start().as_bytes();
    if !prefix
        .get(..3)
        .is_some_and(|s| s.eq_ignore_ascii_case(b"set"))
        && !prefix.starts_with(b"/*")
        && !prefix.starts_with(b"--")
        && !prefix.starts_with(b"#")
    {
        return false;
    }
    let Some(parts) = tokens(sql) else {
        return false;
    };
    parts.first().is_some_and(|part| word(part, "set"))
        && parts.iter().any(|part| {
            word(part, "isolation")
                || word(part, "transaction_isolation")
                || word(part, "tx_isolation")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn isolation_syntax_keeps_scope_level_and_statement_boundaries() {
        assert_eq!(
            setting(" SET /* driver */ TRANSACTION ISOLATION LEVEL read committed;"),
            Some((Scope::Next, Level::ReadCommitted))
        );
        assert_eq!(
            setting("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ"),
            Some((Scope::Session, Level::RepeatableRead))
        );
        for sql in [
            "SET GLOBAL TRANSACTION ISOLATION LEVEL READ COMMITTED",
            "SET TRANSACTION READ ONLY",
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY",
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; DELETE FROM items",
            "SET SESSION transaction_isolation='READ-COMMITTED'",
            "SET TRANSACTION ISOLATION LEVEL ?",
            "/*! SET TRANSACTION ISOLATION LEVEL READ COMMITTED */",
        ] {
            assert!(setting(sql).is_none(), "{sql}");
        }
        assert!(probe("SELECT @@session.tx_isolation"));
        assert!(!probe("SELECT @@global.transaction_isolation"));
    }
}
