//! Pure token expansion for one physical table and its derived projection aliases.
use super::Token;

/// A marker is either the whole identifier or a bounded `_suffix` alias.
pub fn suffix<'a>(token: &'a Token, marker: &str) -> Option<&'a str> {
    let Token::Word(word) = token else {
        return None;
    };
    let suffix = word.strip_prefix(marker)?;
    (suffix.is_empty()
        || suffix.strip_prefix('_').is_some_and(|suffix| {
            !suffix.is_empty()
                && !suffix.contains(marker)
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }))
    .then_some(suffix)
}

/// Derived names are permitted only after AS in the outer SELECT projection.
pub fn projection_alias(template: &[Token], index: usize, marker: &str) -> bool {
    if !template.first().is_some_and(|token| token.is("select"))
        || !index
            .checked_sub(1)
            .is_some_and(|previous| template[previous].is("as"))
        || !template
            .get(index)
            .and_then(|token| suffix(token, marker))
            .is_some_and(|suffix| !suffix.is_empty())
    {
        return false;
    }
    let mut depth = 0usize;
    let mut outer_alias = false;
    for (position, token) in template.iter().enumerate() {
        if token.is("(") {
            depth += 1;
        } else if token.is(")") {
            let Some(parent) = depth.checked_sub(1) else {
                return false;
            };
            depth = parent;
        }
        if position == index {
            outer_alias = depth == 0;
        }
        if depth == 0 && token.is("from") {
            return outer_alias
                && index < position
                && template
                    .get(index + 1)
                    .is_some_and(|next| next.is(",") || next.is("from"));
        }
    }
    false
}

pub fn instantiate(template: &[Token], marker: &str, table: &str) -> Option<Vec<Token>> {
    template
        .iter()
        .map(|token| match suffix(token, marker) {
            Some("") => Some(Token::Word(table.to_owned())),
            Some(suffix) => {
                let alias = format!("{table}{suffix}");
                (alias.len() <= 256).then_some(Token::Word(alias))
            }
            None => Some(token.clone()),
        })
        .collect()
}

pub fn matches_token(template: &Token, actual: &Token, marker: &str, table: &str) -> bool {
    match suffix(template, marker) {
        Some(suffix) => matches!(actual, Token::Word(word)
            if (suffix.is_empty() || word.len() <= 256)
                && word.len() == table.len() + suffix.len()
                && word.starts_with(table) && word.ends_with(suffix)),
        None => template == actual || *template == Token::Placeholder && actual.is_value(),
    }
}

#[derive(Default)]
pub struct Constraints {
    left: Option<String>,
    right: Option<String>,
    shared: bool,
}

impl Constraints {
    /// Physical-table selection stays with the caller, outside token expansion.
    pub fn compatible(
        self,
        left_matches: impl Fn(&str) -> bool,
        right_matches: impl Fn(&str) -> bool,
        ranges_overlap: impl FnOnce() -> bool,
    ) -> bool {
        if self
            .left
            .as_deref()
            .is_some_and(|table| !left_matches(table))
            || self
                .right
                .as_deref()
                .is_some_and(|table| !right_matches(table))
        {
            return false;
        }
        if !self.shared {
            return true;
        }
        match (self.left, self.right) {
            (Some(left), Some(right)) => left == right,
            (Some(table), None) => right_matches(&table),
            (None, Some(table)) => left_matches(&table),
            (None, None) => ranges_overlap(),
        }
    }
}

/// Solve literal aliases before intersecting the complete physical-table ranges.
/// An absent marker preserves every identifier literally, including reserved names.
pub fn overlap(
    left: &[Token],
    left_marker: Option<&str>,
    right: &[Token],
    right_marker: Option<&str>,
) -> Option<Constraints> {
    if left.len() != right.len() {
        return None;
    }
    let mut constraints = Constraints::default();
    for (left, right) in left.iter().zip(right) {
        match (
            left_marker.and_then(|marker| suffix(left, marker)),
            right_marker.and_then(|marker| suffix(right, marker)),
        ) {
            (Some(left), Some(right)) if left == right => constraints.shared = true,
            (Some(_), Some(_)) => return None,
            (Some(suffix), None) => constrain(right, suffix, &mut constraints.left)?,
            (None, Some(suffix)) => constrain(left, suffix, &mut constraints.right)?,
            (None, None)
                if left == right
                    || (*left == Token::Placeholder && right.is_value())
                    || (*right == Token::Placeholder && left.is_value()) => {}
            _ => return None,
        }
    }
    Some(constraints)
}

fn constrain(token: &Token, suffix: &str, binding: &mut Option<String>) -> Option<()> {
    let Token::Word(word) = token else {
        return None;
    };
    let table = word
        .strip_suffix(suffix)
        .filter(|table| !table.is_empty())?;
    if binding.as_deref().is_some_and(|previous| previous != table) {
        return None;
    }
    *binding = Some(table.to_owned());
    Some(())
}
