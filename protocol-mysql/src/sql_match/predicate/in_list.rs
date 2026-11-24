//! Scalar/flat-row IN shape, bound multiset normalization and PREPARE matching.
use super::{Expr, Operand, Token, injective_metadata, operand};
use std::collections::BTreeMap;

pub(super) fn parse(expr: &Expr, list: &[Expr]) -> Option<(Operand, Vec<Operand>)> {
    if let Expr::Tuple(fields) = expr {
        if fields.len() < 2 {
            return None;
        }
        let fields = fields.iter().map(operand).collect::<Option<Vec<_>>>()?;
        if !fields
            .iter()
            .all(|field| matches!(field, Operand::Column(_)))
        {
            return None;
        }
        let values = list
            .iter()
            .map(|row| {
                let Expr::Tuple(row) = row else {
                    return None;
                };
                if row.len() != fields.len() {
                    return None;
                }
                Some(Operand::Tuple(
                    row.iter().map(scalar_value).collect::<Option<_>>()?,
                ))
            })
            .collect::<Option<_>>()?;
        Some((Operand::Tuple(fields), values))
    } else {
        Some((
            operand(expr)?,
            list.iter().map(scalar_value).collect::<Option<_>>()?,
        ))
    }
}

fn scalar_value(expr: &Expr) -> Option<Operand> {
    let value = operand(expr)?;
    matches!(value, Operand::Slot(_) | Operand::Value(_)).then_some(value)
}

pub(super) fn bind(values: &[Operand], tokens: &[Token]) -> Option<Vec<Operand>> {
    let mut values = values
        .iter()
        .map(|value| value.bind(tokens))
        .collect::<Option<Vec<_>>>()?;
    let width = match values.first()? {
        Operand::Tuple(fields) => fields.len(),
        _ => 1,
    };
    // MySQL coercion is component-wise for row comparisons. Different tuple
    // positions may use different types; a position may not mix numbers/bytes
    // across rows. NULL and not-yet-bound PREPARE slots retain their identity.
    for index in 0..width {
        let mut families = 0;
        for value in &values {
            let value = match value {
                Operand::Tuple(fields) => fields.get(index)?,
                value => value,
            };
            families |= match value {
                Operand::Value(Token::Number(_)) => 1,
                Operand::Value(Token::Bytes(_)) => 2,
                Operand::Value(Token::Null | Token::Placeholder) => 0,
                _ => return None,
            };
        }
        if families == 3 {
            return None;
        }
    }
    // Sort complete rows. Never sort fields independently or collapse repeats.
    values.sort();
    Some(values)
}

/// Only an actual literal slot can move. The original row and predicate
/// punctuation stays in place, along with every token outside the list.
pub(super) fn normalize_literal_rows(rows: &[Operand], tokens: &mut [Token]) -> Option<()> {
    let sorted = bind(rows, tokens)?;
    for (original, sorted) in rows.iter().zip(sorted) {
        let (Operand::Tuple(original), Operand::Tuple(sorted)) = (original, sorted) else {
            return None;
        };
        for (slot, value) in original.iter().zip(sorted) {
            let (Operand::Slot(slot), Operand::Value(value @ (Token::Number(_) | Token::Bytes(_)))) =
                (slot, value)
            else {
                return None;
            };
            *tokens.get_mut(*slot)? = value;
        }
    }
    Some(())
}

fn has_placeholder(value: &Operand) -> bool {
    match value {
        Operand::Tuple(fields) => fields.iter().any(has_placeholder),
        _ => *value == Operand::Value(Token::Placeholder),
    }
}

fn all_placeholders(value: &Operand) -> bool {
    match value {
        Operand::Tuple(fields) => fields.iter().all(all_placeholders),
        _ => *value == Operand::Value(Token::Placeholder),
    }
}

pub(super) fn metadata_matches(actual: &[Operand], recorded: &[Operand]) -> bool {
    if actual.len() != recorded.len() {
        return false;
    }
    let mut counts = BTreeMap::new();
    for value in recorded {
        *counts.entry(value).or_insert(0_usize) += 1;
    }
    // Concrete rows claim exact occurrences first. Fully bound and fully
    // parameterized lists use this fast path even for large IN lists.
    let mut partial = Vec::new();
    for value in actual {
        if !has_placeholder(value) {
            let Some(count) = counts.get_mut(value) else {
                return false;
            };
            let Some(left) = count.checked_sub(1) else {
                return false;
            };
            *count = left;
        } else if !all_placeholders(value) {
            partial.push(value);
        }
    }
    if partial.is_empty() {
        return true;
    }
    let remaining = counts
        .into_iter()
        .flat_map(|(value, count)| std::iter::repeat_n(value, count))
        .collect::<Vec<_>>();
    // A greedy match can reject ((?,2),(1,?)) against ((1,2),(3,2)). Match
    // partial rows injectively; fully unknown rows take any unused occurrences.
    // Bound graph work to 64 partial rows and 4096 possible assignments.
    injective_metadata(&partial, &remaining, |a, r| a.metadata_matches(r))
}
