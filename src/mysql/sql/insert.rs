//! Conservative extraction of literal columns from one explicit-column INSERT.
use std::collections::{BTreeMap, BTreeSet};

use super::{Token, tokens};

pub(crate) fn row(sql: &str) -> Option<(String, BTreeMap<String, Token>)> {
    let ts = tokens(sql)?;
    let mut it = ts.iter();
    if !it.next()?.is("insert") || !it.next()?.is("into") {
        return None;
    }
    let table = identifier(it.next()?)?.to_string();
    if !it.next()?.is("(") {
        return None;
    }
    let mut columns = Vec::new();
    loop {
        columns.push(identifier(it.next()?)?.to_string());
        let delimiter = it.next()?;
        if delimiter.is(")") {
            break;
        }
        if !delimiter.is(",") || columns.len() >= 128 {
            return None;
        }
    }
    if !it.next()?.is("values") || !it.next()?.is("(") {
        return None;
    }
    let mut values = Vec::new();
    loop {
        let value = it.next()?;
        // ORM inserts often set unrelated audit columns with NOW(). Consume
        // only these known, argument-free timestamp expressions, without
        // exposing a value that could satisfy an identity or row predicate.
        let value = if value.is_value() {
            Some(value.clone())
        } else if matches!(value, Token::Word(name) if name.eq_ignore_ascii_case("now") || name.eq_ignore_ascii_case("current_timestamp"))
            && it.next()?.is("(")
            && it.next()?.is(")")
        {
            None
        } else {
            return None;
        };
        values.push(value);
        let delimiter = it.next()?;
        if delimiter.is(")") {
            break;
        }
        if !delimiter.is(",") || values.len() >= 128 {
            return None;
        }
    }
    if columns.len() != values.len() {
        return None;
    }
    if let Some(end) = it.next()
        && (!end.is(";") || it.next().is_some())
    {
        return None;
    }
    if columns.iter().collect::<BTreeSet<_>>().len() != columns.len() {
        return None;
    }
    let values = columns
        .into_iter()
        .zip(values)
        .filter_map(|(column, value)| value.map(|value| (column, value)))
        .collect();
    Some((table, values))
}

fn identifier(token: &Token) -> Option<&str> {
    match token {
        Token::Word(s) | Token::Identifier(s) => Some(s),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_literals_and_rejects_ambiguous_or_executable_forms() {
        assert!(row("INSERT INTO jobs_0001 (id,`role`) VALUES (12,'ASSISTANT');").is_some());
        let (_, values) = row("INSERT INTO jobs (id,role,created_at,updated_at) VALUES (12,'ASSISTANT',now(),CURRENT_TIMESTAMP())").unwrap();
        assert_eq!(values.get("id"), Some(&Token::Number("12".into())));
        assert!(!values.contains_key("created_at"));
        assert!(!values.contains_key("updated_at"));
        for sql in [
            "INSERT INTO jobs (id) VALUES (1),(2)",
            "INSERT INTO jobs (id) VALUES (?)",
            "INSERT INTO jobs (id) VALUES (1) ON DUPLICATE KEY UPDATE id=2",
            "INSERT INTO jobs (id,id) VALUES (1,2)",
            "INSERT INTO jobs (id) SELECT 1",
            "INSERT INTO jobs (id) VALUES (1); DELETE FROM jobs",
            "INSERT /*! IGNORE */ INTO jobs (id) VALUES (1)",
            "INSERT INTO jobs (id) VALUES (1+2)",
            "INSERT INTO jobs (id,created_at) VALUES (12,NOW(1))",
            "INSERT INTO jobs (id,created_at) VALUES (12,SLEEP(1))",
        ] {
            assert!(row(sql).is_none(), "{sql}");
        }
    }
}
