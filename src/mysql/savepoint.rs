//! Bounded parsing and lifetime rules for MySQL transaction savepoints.
use super::sql::{Token, tokens};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Create,
    Release,
    Rollback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Command {
    pub kind: Kind,
    pub name: String,
}

pub(crate) fn parse(sql: &str) -> Option<Command> {
    let leading = sql.split_whitespace().next()?;
    if !["savepoint", "release", "rollback"]
        .iter()
        .any(|word| leading.eq_ignore_ascii_case(word))
    {
        return None;
    }
    if sql.len() > 1024 {
        return None;
    }
    let tokens = tokens(sql)?
        .into_iter()
        .map(|token| match token {
            Token::Word(word) => Token::Word(word.to_ascii_lowercase()),
            other => other,
        })
        .collect::<Vec<_>>();
    let (kind, name) = match tokens.as_slice() {
        [a, name] if a.is("savepoint") => (Kind::Create, name),
        [a, b, name] if a.is("release") && b.is("savepoint") => (Kind::Release, name),
        [a, b, name] if a.is("rollback") && b.is("to") => (Kind::Rollback, name),
        [a, b, c, name] if a.is("rollback") && b.is("to") && c.is("savepoint") => {
            (Kind::Rollback, name)
        }
        [a, b, c, name] if a.is("rollback") && b.is("work") && c.is("to") => (Kind::Rollback, name),
        [a, b, c, d, name]
            if a.is("rollback") && b.is("work") && c.is("to") && d.is("savepoint") =>
        {
            (Kind::Rollback, name)
        }
        _ => return None,
    };
    let (Token::Word(name) | Token::Identifier(name)) = name else {
        return None;
    };
    if name.is_empty() || name.chars().count() > 64 {
        return None;
    }
    Some(Command {
        kind,
        name: name.to_ascii_lowercase(),
    })
}

#[derive(Debug, Default)]
pub(crate) struct Names(Vec<String>);

impl Names {
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
    pub(crate) fn observe(&mut self, command: &Command) -> bool {
        let found = self.0.iter().position(|name| *name == command.name);
        match (command.kind, found) {
            (Kind::Create, found) => {
                if let Some(index) = found {
                    self.0.remove(index);
                }
                if self.0.len() >= 1024 {
                    return false;
                }
                self.0.push(command.name.clone());
            }
            (Kind::Release, Some(index)) => {
                self.0.remove(index);
            }
            (Kind::Rollback, Some(index)) => self.0.truncate(index + 1),
            _ => return false,
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_only_complete_controls_and_preserves_savepoint_lifetimes() {
        for sql in [
            "SAVEPOINT 's'",
            "SAVEPOINT s; COMMIT",
            "RELEASE SAVEPOINT s extra",
            "SAVEPOINT ?",
            "/*! SAVEPOINT s */",
        ] {
            assert!(parse(sql).is_none(), "{sql}");
        }
        let mut names = Names::default();
        for sql in [
            "SAVEPOINT `A`",
            "SAVEPOINT b",
            "ROLLBACK WORK TO SAVEPOINT a",
            "RELEASE SAVEPOINT a",
        ] {
            assert!(names.observe(&parse(sql).unwrap()));
        }
        assert!(!names.observe(&parse("RELEASE SAVEPOINT b").unwrap()));
        assert!(!names.observe(&parse("ROLLBACK TO a").unwrap()));
    }
}
