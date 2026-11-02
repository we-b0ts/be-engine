//! Conservative SQL families exclude structurally impossible native candidates.
//! Unknown syntax keeps the complete existing matcher and policy path.
use crate::mysql::sql::{Token, bounds::tokens};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::replay::mysql) enum Family {
    Select,
    Write,
    Set,
    Begin,
    End,
}

pub(in crate::replay::mysql) fn classify(sql: Option<&str>) -> Option<Family> {
    let tokens = tokens(sql?)?;
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
}
