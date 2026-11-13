//! Conservative SQL families exclude structurally impossible native candidates.
//! Unknown syntax keeps the complete existing matcher and policy path.
use crate::sql::{Token, projection::identifier, tokens_shared};
use std::hash::{DefaultHasher, Hash, Hasher};

#[derive(Debug)]
pub struct SelectHint {
    pub table: String,
    pub scalar_shape: u64,
}

impl SelectHint {
    pub fn from_tokens(tokens: &[Token]) -> Option<Self> {
        let table = select_table(tokens)?.to_owned();
        let mut shape = DefaultHasher::new();
        tokens.len().hash(&mut shape);
        for token in tokens {
            if token.is_value() || *token == Token::Placeholder {
                false.hash(&mut shape);
            } else {
                true.hash(&mut shape);
                token.hash(&mut shape);
            }
        }
        Some(Self {
            table,
            scalar_shape: shape.finish(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Select,
    Write,
    Set,
    Begin,
    End,
}

pub fn classify(sql: Option<&str>) -> Option<Family> {
    let tokens = bounded_tokens(sql?)?;
    classify_tokens(&tokens)
}

pub fn bounded_tokens(sql: &str) -> Option<std::sync::Arc<Vec<Token>>> {
    if sql.len() > crate::sql::bounds::MAX_STATEMENT_BYTES {
        return None;
    }
    tokens_shared(sql).filter(|tokens| tokens.len() <= crate::sql::bounds::MAX_TOKENS)
}

pub fn classify_tokens(tokens: &[Token]) -> Option<Family> {
    let Token::Word(word) = tokens.first()? else {
        return None;
    };
    match word.as_str() {
        "select" => Some(Family::Select),
        "insert" | "update" | "delete" | "replace" => Some(Family::Write),
        "set" => Some(Family::Set),
        "begin" if tokens.len() == 1 => Some(Family::Begin),
        "start" if tokens.len() == 2 && tokens[1].is("transaction") => Some(Family::Begin),
        "commit" | "rollback" if tokens.len() == 1 => Some(Family::End),
        _ => None,
    }
}

/// Prove the physical relation for an unambiguous single-table SELECT.
/// Complex statements retain the existing candidate path.
pub fn select_table(tokens: &[Token]) -> Option<&str> {
    if !tokens.first()?.is("select")
        || tokens.iter().skip(1).any(|token| {
            [
                "select",
                "join",
                "union",
                "intersect",
                "except",
                "into",
                ";",
            ]
            .iter()
            .any(|word| token.is(word))
        })
    {
        return None;
    }
    let from = tokens.iter().position(|token| token.is("from"))?;
    if tokens[from + 1..].iter().any(|token| token.is("from")) {
        return None;
    }
    let mut relation = &tokens[from + 1..];
    let mut table = identifier(relation.first()?)?;
    relation = &relation[1..];
    if relation.first().is_some_and(|token| token.is(".")) {
        table = identifier(relation.get(1)?)?;
        relation = &relation[2..];
    }
    let tail = |tokens: &[Token]| {
        tokens.first().is_none_or(|token| {
            ["where", "order", "limit", "group", "having"]
                .iter()
                .any(|word| token.is(word))
        })
    };
    if !tail(relation) {
        if relation.first()?.is("as") {
            relation = &relation[1..];
        }
        identifier(relation.first()?)?;
        if !tail(&relation[1..]) {
            return None;
        }
    }
    Some(table)
}

pub fn select_hint(sql: &str) -> Option<SelectHint> {
    SelectHint::from_tokens(&bounded_tokens(sql)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_keep_transaction_aliases_and_leave_uncertain_syntax_unfiltered() {
        for sql in ["begin", "START TRANSACTION", "/* driver */ BEGIN;"] {
            assert_eq!(classify(Some(sql)), Some(Family::Begin), "{sql}");
        }
        assert_eq!(classify(Some("commit")), classify(Some("rollback")));
        for sql in [
            "WITH r AS (SELECT id FROM tasks) SELECT * FROM r",
            "/*!40101 SET NAMES utf8mb4 */",
            "ROLLBACK TO SAVEPOINT s1",
            "CALL business()",
        ] {
            assert_eq!(classify(Some(sql)), None, "{sql}");
        }
        assert_eq!(classify(None), None);
    }

    #[test]
    fn table_hint_requires_one_unambiguous_physical_relation() {
        assert_eq!(
            select_hint("SELECT t.id FROM app.`tasks` AS t WHERE t.id = ?")
                .as_ref()
                .map(|hint| hint.table.as_str()),
            Some("tasks")
        );
        for sql in [
            "SELECT a.id FROM alpha a, beta b WHERE a.id = b.id",
            "SELECT a.id FROM alpha a JOIN beta b ON a.id = b.id",
            "SELECT id FROM alpha WHERE id IN (SELECT id FROM beta)",
            "SELECT EXTRACT(YEAR FROM created) FROM alpha",
            "SELECT id FROM alpha UNION SELECT id FROM beta",
            "SELECT id FROM alpha; SELECT id FROM beta",
        ] {
            assert!(select_hint(sql).is_none(), "{sql}");
        }
    }

    #[test]
    fn exact_shape_preserves_predicates_and_ignores_scalar_value_spelling() {
        let shape = |sql| select_hint(sql).unwrap().scalar_shape;
        let actual = shape("SELECT id FROM tasks WHERE id=? AND name=?");
        assert_eq!(
            actual,
            shape("select id from tasks where id=7 and name='source'")
        );
        assert_ne!(actual, shape("SELECT id FROM tasks WHERE id=? AND owner=?"));
        assert_ne!(
            actual,
            shape("SELECT id FROM tasks WHERE id IN (?) AND name=?")
        );
    }
}
