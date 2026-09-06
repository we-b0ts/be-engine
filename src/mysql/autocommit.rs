//! Recognize one literal, session-scoped AUTOCOMMIT assignment.
use super::sql::{Token, tokens};

pub(crate) fn assignment(sql: &str) -> Option<bool> {
    if sql.len() > 4096 {
        return None;
    }
    let head = sql.trim_start();
    if !head
        .get(..3)
        .is_some_and(|head| head.eq_ignore_ascii_case("set"))
        && !head.starts_with(['/', '-', '#'])
    {
        return None;
    }
    let tokens = tokens(sql)?;
    let (set, mut rest) = tokens.split_first()?;
    if !set.is("set") {
        return None;
    }
    if rest
        .first()
        .is_some_and(|t| t.is("session") || t.is("local"))
    {
        rest = &rest[1..];
    } else if rest.first().is_some_and(|t| t.is("@@")) {
        rest = &rest[1..];
        if rest
            .first()
            .is_some_and(|t| t.is("session") || t.is("local"))
        {
            if !rest.get(1).is_some_and(|t| t.is(".")) {
                return None;
            }
            rest = &rest[2..];
        }
    }
    match rest {
        [name, equals, Token::Number(value)] if name.is("autocommit") && equals.is("=") => {
            match value.as_str() {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_single_literal_session_assignments() {
        for prefix in [
            "SET",
            "set session",
            "SET LOCAL",
            "SET @@",
            "SET @@session.",
        ] {
            for value in [0, 1] {
                assert_eq!(
                    assignment(&format!("{prefix} autocommit = {value};")),
                    Some(value == 1)
                );
            }
        }
        for sql in [
            "SET GLOBAL autocommit=1",
            "SET @@global.autocommit=0",
            "SET autocommit=?",
            "SET autocommit=@value",
            "SET autocommit=2",
            "SET autocommit=0,sql_mode=''",
            "SET autocommit=0; DELETE FROM users",
            "SET autocommit=1 /*!; COMMIT */",
            "SET SESSION @@autocommit=0",
        ] {
            assert_eq!(assignment(sql), None, "{sql}");
        }
    }
}
