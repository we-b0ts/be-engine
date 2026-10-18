//! Bounded full-AST matching for unordered IN lists in supported complex queries.
//! The complete query AST stays exact; only scalar/flat-tuple list order changes.
use super::MAX_SQL_TOKENS;
use crate::mysql::sql::{Token, render};
use sqlparser::{
    ast::{
        BinaryOperator, Expr, GroupByExpr, Query, Select, SelectFlavor, SelectItem, SetExpr,
        Statement, TableFactor, Value, Visit, Visitor, visit_expressions, visit_expressions_mut,
    },
    dialect::MySqlDialect,
    parser::Parser,
};
use std::ops::ControlFlow;

#[derive(Clone, Debug)]
pub(super) struct Template {
    query: Box<Query>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Key {
    query: Box<Query>,
}

impl Template {
    pub(super) fn parse(tokens: &[Token]) -> Option<Self> {
        if tokens.len() > MAX_SQL_TOKENS || !bounded_parentheses(tokens) {
            return None;
        }
        let parser_tokens = tokens
            .iter()
            .enumerate()
            .map(|(index, token)| match token {
                Token::Number(_) | Token::Bytes(_) | Token::Placeholder => {
                    Token::Symbol(format!("?{index}"))
                }
                _ => token.clone(),
            })
            .collect::<Vec<_>>();
        let dialect = MySqlDialect {};
        let mut statements = Parser::new(&dialect)
            .with_recursion_limit(64)
            .try_with_sql(&render(&parser_tokens))
            .ok()?
            .parse_statements()
            .ok()?;
        if statements.len() != 1 {
            return None;
        }
        let Statement::Query(query) = statements.pop()? else {
            return None;
        };
        let nested_exists = validate_nested_query_tree(&query).is_some();
        let union_all = validate_union_query_tree(&query).is_some();
        (nested_exists || union_all).then_some(Self { query })
    }

    pub(super) fn bind(&self, tokens: &[Token]) -> Option<Key> {
        let mut query = self.query.clone();
        let result = visit_expressions_mut(&mut query, |expr| {
            let Expr::Value(value) = expr else {
                return ControlFlow::Continue(());
            };
            let Value::Placeholder(slot) = &value.value else {
                return ControlFlow::Continue(());
            };
            let Some(index) = slot.strip_prefix('?').and_then(|s| s.parse::<usize>().ok()) else {
                return ControlFlow::Break(());
            };
            let Some(bound) = tokens.get(index).and_then(bound_value) else {
                return ControlFlow::Break(());
            };
            value.value = bound;
            ControlFlow::Continue(())
        });
        if result.is_break() || !canonicalize_lists(&mut query) {
            return None;
        }
        Some(Key { query })
    }
}

impl Key {
    pub(super) fn metadata_matches(&self, recorded: &Self) -> bool {
        let (Some((actual_shape, actual_values)), Some((recorded_shape, recorded_values))) =
            (shape(&self.query), shape(&recorded.query))
        else {
            return false;
        };
        actual_shape == recorded_shape
            && actual_values.len() == recorded_values.len()
            && actual_values
                .iter()
                .zip(recorded_values)
                .all(|(actual, recorded)| {
                    matches!(actual, Value::Placeholder(_)) || actual == &recorded
                })
    }
}

fn bounded_parentheses(tokens: &[Token]) -> bool {
    let mut depth = 0_usize;
    for token in tokens {
        if token.is("(") {
            depth += 1;
            if depth > 32 {
                return false;
            }
        } else if token.is(")") {
            let Some(next) = depth.checked_sub(1) else {
                return false;
            };
            depth = next;
        }
    }
    depth == 0
}

fn validate_nested_query_tree(query: &Query) -> Option<()> {
    #[derive(Default)]
    struct Validator {
        queries: usize,
        exists: usize,
        count_wrappers: usize,
        nested_in: bool,
    }
    impl Visitor for Validator {
        type Break = ();

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
            self.queries += 1;
            let Some(select) = validate_nested_select(query) else {
                return ControlFlow::Break(());
            };
            self.count_wrappers += usize::from(derived_count(select));
            self.nested_in |= select
                .selection
                .as_ref()
                .is_some_and(|selection| has_nested_in_anchor(selection, false));
            ControlFlow::Continue(())
        }

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
            match expr {
                Expr::Exists { .. } => self.exists += 1,
                Expr::Subquery(_) | Expr::InSubquery { .. } => {
                    return ControlFlow::Break(());
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
    }
    let mut validator = Validator::default();
    query.visit(&mut validator).is_continue().then_some(())?;
    (validator.queries == validator.exists + validator.count_wrappers + 1
        && (validator.nested_in || validator.count_wrappers > 0))
        .then_some(())
}

fn validate_nested_select(query: &Query) -> Option<&Select> {
    if query.with.is_some()
        || query.fetch.is_some()
        || !query.locks.is_empty()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
    {
        return None;
    }
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let empty_group =
        matches!(&select.group_by, GroupByExpr::Expressions(items, _) if items.is_empty());
    let count_wrapper = derived_count(select);
    if select.flavor != SelectFlavor::Standard
        || !select.optimizer_hints.is_empty()
        || select.distinct.is_some()
        || select.select_modifiers.is_some()
        || select.top.is_some()
        || select.exclude.is_some()
        || select.into.is_some()
        || select.from.len() != 1
        || !count_wrapper
            && (!matches!(
                select.from[0].relation,
                TableFactor::Table { args: None, .. }
            ) || select.from[0]
                .joins
                .iter()
                .any(|join| !matches!(join.relation, TableFactor::Table { args: None, .. })))
        || !select.lateral_views.is_empty()
        || select.prewhere.is_some()
        || !count_wrapper && select.selection.is_none()
        || !select.connect_by.is_empty()
        || !empty_group
        || !select.cluster_by.is_empty()
        || !select.distribute_by.is_empty()
        || !select.sort_by.is_empty()
        || select.having.is_some()
        || !select.named_window.is_empty()
        || select.qualify.is_some()
        || select.value_table_mode.is_some()
        || select.projection.is_empty()
        || !count_wrapper
            && select.projection.iter().any(|item| match item {
                SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                    !matches!(
                        expr,
                        Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_)
                    )
                }
                SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => false,
                _ => true,
            })
    {
        return None;
    }
    Some(select)
}

/// A count wrapper adds exactly one derived query scope. Its full AST, including
/// aliases, stays strict; the child must independently pass the same validation.
fn derived_count(select: &Select) -> bool {
    select.from.len() == 1
        && select.from[0].joins.is_empty()
        && matches!(
            select.from[0].relation,
            TableFactor::Derived { lateral: false, .. }
        )
        && select.selection.is_none()
        && matches!(select.projection.as_slice(),
            [SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }]
                if expr.to_string().eq_ignore_ascii_case("count(*)"))
}

fn validate_union_query_tree(query: &Query) -> Option<()> {
    #[derive(Default)]
    struct Validator {
        union_all: bool,
    }
    impl Visitor for Validator {
        type Break = ();

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
            if validate_union_query(query).is_none() {
                return ControlFlow::Break(());
            }
            self.union_all |= contains_union_all(&query.body);
            ControlFlow::Continue(())
        }

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
            if matches!(
                expr,
                Expr::Exists { .. } | Expr::Subquery(_) | Expr::InSubquery { .. }
            ) {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        }
    }
    let mut validator = Validator::default();
    query.visit(&mut validator).is_continue().then_some(())?;
    validator.union_all.then_some(())
}

fn validate_union_query(query: &Query) -> Option<()> {
    if query.with.is_some()
        || !query.locks.is_empty()
        || query.fetch.is_some()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
    {
        return None;
    }
    validate_union_body(&query.body)
}

fn validate_union_body(body: &SetExpr) -> Option<()> {
    match body {
        SetExpr::Select(select) => validate_union_select(select),
        SetExpr::Query(query) => validate_union_query(query),
        SetExpr::SetOperation {
            left,
            op: sqlparser::ast::SetOperator::Union,
            set_quantifier: sqlparser::ast::SetQuantifier::All,
            right,
        } => {
            validate_union_body(left)?;
            validate_union_body(right)
        }
        _ => None,
    }
}

fn validate_union_select(select: &Select) -> Option<()> {
    let empty_group =
        matches!(&select.group_by, GroupByExpr::Expressions(items, _) if items.is_empty());
    (select.flavor == SelectFlavor::Standard
        && select.optimizer_hints.is_empty()
        && select.distinct.is_none()
        && select.select_modifiers.is_none()
        && select.top.is_none()
        && select.exclude.is_none()
        && select.into.is_none()
        && select.lateral_views.is_empty()
        && select.prewhere.is_none()
        && select.connect_by.is_empty()
        && empty_group
        && select.cluster_by.is_empty()
        && select.distribute_by.is_empty()
        && select.sort_by.is_empty()
        && select.having.is_none()
        && select.named_window.is_empty()
        && select.qualify.is_none()
        && select.value_table_mode.is_none()
        && !select.projection.is_empty())
    .then_some(())
}

fn contains_union_all(body: &SetExpr) -> bool {
    match body {
        SetExpr::Query(query) => contains_union_all(&query.body),
        SetExpr::SetOperation {
            op: sqlparser::ast::SetOperator::Union,
            set_quantifier: sqlparser::ast::SetQuantifier::All,
            ..
        } => true,
        _ => false,
    }
}

fn select(query: &Query) -> Option<&Select> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    Some(select)
}

fn has_nested_in_anchor(expr: &Expr, inside_or: bool) -> bool {
    match expr {
        Expr::Nested(expr) => has_nested_in_anchor(expr, inside_or),
        Expr::BinaryOp { left, op, right } => {
            let inside_or = inside_or || *op == BinaryOperator::Or;
            has_nested_in_anchor(left, inside_or) || has_nested_in_anchor(right, inside_or)
        }
        Expr::UnaryOp { expr, .. } => has_nested_in_anchor(expr, inside_or),
        Expr::Exists { subquery, .. } if inside_or => select(subquery)
            .and_then(|select| select.selection.as_ref())
            .is_some_and(contains_reorderable_in),
        _ => false,
    }
}

fn contains_reorderable_in(expr: &Expr) -> bool {
    let mut found = false;
    let _ = visit_expressions(expr, |expr| {
        if reorderable_in(expr).is_some() {
            found = true;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    });
    found
}

fn canonicalize_lists(query: &mut Query) -> bool {
    let mut normalized = 0_usize;
    let result = visit_expressions_mut(query, |expr| {
        let Some((width, list)) = reorderable_in_mut(expr) else {
            return ControlFlow::Continue(());
        };
        if normalize_list(width, list).is_none() {
            return ControlFlow::Break(());
        }
        normalized += 1;
        ControlFlow::Continue(())
    });
    result.is_continue() && normalized > 0
}

fn reorderable_in(expr: &Expr) -> Option<(usize, &[Expr])> {
    let Expr::InList { expr, list, .. } = expr else {
        return None;
    };
    in_shape(expr, list).map(|width| (width, list.as_slice()))
}

fn reorderable_in_mut(expr: &mut Expr) -> Option<(usize, &mut Vec<Expr>)> {
    let Expr::InList { expr, list, .. } = expr else {
        return None;
    };
    let width = in_shape(expr, list)?;
    Some((width, list))
}

fn in_shape(left: &Expr, list: &[Expr]) -> Option<usize> {
    if list.is_empty() {
        return None;
    }
    let width = match left {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => 1,
        Expr::Tuple(fields)
            if fields.len() >= 2
                && fields.iter().all(|field| {
                    matches!(field, Expr::Identifier(_) | Expr::CompoundIdentifier(_))
                }) =>
        {
            fields.len()
        }
        _ => return None,
    };
    list.iter()
        .all(|value| {
            if width == 1 {
                scalar(value)
            } else {
                matches!(value, Expr::Tuple(fields) if fields.len() == width && fields.iter().all(scalar))
            }
        })
        .then_some(width)
}

fn scalar(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Value(value)
            if matches!(
                value.value,
                Value::Number(..)
                    | Value::HexStringLiteral(_)
                    | Value::Null
                    | Value::Placeholder(_)
            )
    )
}

fn normalize_list(width: usize, list: &mut [Expr]) -> Option<()> {
    for index in 0..width {
        let mut families = 0_u8;
        for value in list.iter() {
            let value = if width == 1 {
                value
            } else {
                let Expr::Tuple(fields) = value else {
                    return None;
                };
                fields.get(index)?
            };
            families |= match value {
                Expr::Value(value) => match value.value {
                    Value::Number(..) => 1,
                    Value::HexStringLiteral(_) => 2,
                    Value::Null | Value::Placeholder(_) => 0,
                    _ => return None,
                },
                _ => return None,
            };
        }
        if families == 3 {
            return None;
        }
    }
    list.sort();
    Some(())
}

fn bound_value(token: &Token) -> Option<Value> {
    match token {
        Token::Number(value) => Some(Value::Number(value.clone(), false)),
        Token::Bytes(value) => Some(Value::HexStringLiteral(hex(value))),
        Token::Null => Some(Value::Null),
        Token::Placeholder => Some(Value::Placeholder("?".into())),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn shape(query: &Query) -> Option<(Box<Query>, Vec<Value>)> {
    let mut shape = Box::new(query.clone());
    let mut values = Vec::new();
    let result = visit_expressions_mut(&mut shape, |expr| {
        let Expr::Value(value) = expr else {
            return ControlFlow::Continue(());
        };
        if matches!(
            value.value,
            Value::Number(..) | Value::HexStringLiteral(_) | Value::Placeholder(_)
        ) {
            values.push(value.value.clone());
            value.value = Value::Placeholder("?".into());
        }
        ControlFlow::<()>::Continue(())
    });
    result.is_continue().then_some((shape, values))
}
