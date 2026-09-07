//! Bounded SQL effect analysis, independent of predicate equivalence.
//! This is an effect check, not SQL equivalence or a general transaction model.
use crate::mysql::sql;
use sqlparser::{
    ast::{
        BinaryOperator, Distinct, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments,
        GroupByExpr, JoinConstraint, JoinOperator, LimitClause, OrderByKind, Select, SelectItem,
        SetExpr, SetOperator, SetQuantifier, Statement, TableFactor, UnaryOperator, WindowSpec,
        WindowType,
    },
    dialect::MySqlDialect,
    parser::Parser,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Effect {
    ReadOnly,
    StateChange,
    Unknown,
}

pub(super) fn classify(sql: &str) -> Effect {
    if sql.len() > 64 * 1024 {
        return Effect::Unknown;
    }
    // The shared scanner rejects executable comments/hints and bounds the
    // parser input. Parse original spelling so quoted identifiers stay quoted.
    let Some(tokens) = sql::tokens(sql).filter(|tokens| tokens.len() <= 4096) else {
        return Effect::Unknown;
    };
    if tokens
        .iter()
        .any(|t| ["@", "@@", ":=", "||", "&&"].iter().any(|s| t.is(s)))
    {
        return Effect::Unknown;
    }
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
    if !query.locks.is_empty()
        || matches!(&*query.body, SetExpr::Select(select) if select.into.is_some())
    {
        return Effect::StateChange;
    }
    if read_query(query, 0) {
        Effect::ReadOnly
    } else {
        Effect::Unknown
    }
}

fn read_query(query: &sqlparser::ast::Query, depth: usize) -> bool {
    let pure = |expr: &Expr| expression(expr, depth);
    if depth > 32
        || query.with.is_some()
        || query.fetch.is_some()
        || !query.locks.is_empty()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
    {
        return false;
    }
    if !read_set(&query.body, depth) {
        return false;
    }
    if let Some(order) = &query.order_by {
        let OrderByKind::Expressions(exprs) = &order.kind else {
            return false;
        };
        if order.interpolate.is_some()
            || !exprs
                .iter()
                .all(|expr| pure(&expr.expr) && expr.with_fill.is_none())
        {
            return false;
        }
    }
    match &query.limit_clause {
        None => true,
        Some(LimitClause::LimitOffset {
            limit,
            offset,
            limit_by,
        }) => {
            limit_by.is_empty()
                && limit.as_ref().is_none_or(pure)
                && offset.as_ref().is_none_or(|offset| pure(&offset.value))
        }
        Some(LimitClause::OffsetCommaLimit { offset, limit }) => pure(offset) && pure(limit),
    }
}

fn read_set(body: &SetExpr, depth: usize) -> bool {
    let mut pending = vec![body];
    while let Some(body) = pending.pop() {
        match body {
            SetExpr::Select(select) if read_select(select, depth) => {}
            SetExpr::Query(query) if read_query(query, depth + 1) => {}
            SetExpr::SetOperation {
                left,
                op: SetOperator::Union,
                set_quantifier: SetQuantifier::All | SetQuantifier::Distinct | SetQuantifier::None,
                right,
            } => {
                pending.push(left);
                pending.push(right);
            }
            _ => return false,
        }
    }
    true
}

fn read_table(table: &TableFactor, depth: usize) -> bool {
    match table {
        TableFactor::Table {
            args: None,
            with_hints,
            version: None,
            with_ordinality: false,
            partitions,
            json_path: None,
            sample: None,
            index_hints,
            ..
        } => with_hints.is_empty() && partitions.is_empty() && index_hints.is_empty(),
        TableFactor::Derived {
            lateral: false,
            subquery,
            ..
        } => read_query(subquery, depth + 1),
        _ => false,
    }
}

fn read_select(select: &Select, depth: usize) -> bool {
    let pure = |expr: &Expr| expression(expr, depth);
    if !select.optimizer_hints.is_empty()
        || select
            .distinct
            .as_ref()
            .is_some_and(|d| !matches!(d, Distinct::Distinct | Distinct::All))
        || select.select_modifiers.is_some()
        || select.top.is_some()
        || select.exclude.is_some()
        || select.into.is_some()
        || !select.lateral_views.is_empty()
        || select.prewhere.is_some()
        || !select.connect_by.is_empty()
        || !select.cluster_by.is_empty()
        || !select.distribute_by.is_empty()
        || !select.sort_by.is_empty()
        || !select.named_window.is_empty()
        || select.qualify.is_some()
        || select.value_table_mode.is_some()
        || !matches!(&select.group_by, GroupByExpr::Expressions(exprs, modifiers)
            if modifiers.is_empty() && exprs.iter().all(pure))
        || select.from.is_empty()
    {
        return false;
    }
    for table in &select.from {
        if !read_table(&table.relation, depth) {
            return false;
        }
        for join in &table.joins {
            let constraint = match &join.join_operator {
                JoinOperator::Join(c)
                | JoinOperator::Inner(c)
                | JoinOperator::Left(c)
                | JoinOperator::LeftOuter(c)
                | JoinOperator::Right(c)
                | JoinOperator::RightOuter(c)
                | JoinOperator::CrossJoin(c) => c,
                _ => return false,
            };
            if join.global
                || !read_table(&join.relation, depth)
                || !match constraint {
                    JoinConstraint::On(expr) => pure(expr),
                    JoinConstraint::Using(_) | JoinConstraint::Natural | JoinConstraint::None => {
                        true
                    }
                }
            {
                return false;
            }
        }
    }
    if select.projection.is_empty()
        || !select.projection.iter().all(|item| match item {
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => pure(expr),
            SelectItem::Wildcard(options) | SelectItem::QualifiedWildcard(_, options) => {
                *options == Default::default()
            }
            _ => false,
        })
        || !select.selection.as_ref().is_none_or(pure)
        || !select.having.as_ref().is_none_or(pure)
    {
        return false;
    }
    true
}

fn atom(expr: &Expr) -> bool {
    // No functions, subqueries, session-variable reads/assignments or calls
    // hidden inside ordering/pagination/projection expressions.
    matches!(
        expr,
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_)
    )
}

// Walk expression width iteratively: a long OR/AND chain is not nested SQL.
// Subqueries remain bounded separately and every subtree must prove pure.
fn expression(expr: &Expr, depth: usize) -> bool {
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        match expr {
            Expr::Nested(expr)
            | Expr::UnaryOp {
                op: UnaryOperator::Not | UnaryOperator::Plus | UnaryOperator::Minus,
                expr,
            }
            | Expr::IsNull(expr)
            | Expr::IsNotNull(expr)
            | Expr::IsTrue(expr)
            | Expr::IsNotTrue(expr)
            | Expr::IsFalse(expr)
            | Expr::IsNotFalse(expr)
            | Expr::IsUnknown(expr)
            | Expr::IsNotUnknown(expr) => pending.push(expr),
            Expr::BinaryOp {
                left,
                op:
                    BinaryOperator::And
                    | BinaryOperator::Or
                    | BinaryOperator::Plus
                    | BinaryOperator::Minus
                    | BinaryOperator::Multiply
                    | BinaryOperator::Divide
                    | BinaryOperator::Modulo
                    | BinaryOperator::Eq
                    | BinaryOperator::NotEq
                    | BinaryOperator::Lt
                    | BinaryOperator::LtEq
                    | BinaryOperator::Gt
                    | BinaryOperator::GtEq
                    | BinaryOperator::Spaceship,
                right,
            } => {
                pending.push(left);
                pending.push(right);
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                pending.extend([expr.as_ref(), low.as_ref(), high.as_ref()]);
            }
            Expr::InList { expr, list, .. } => {
                let valid = if let Expr::Tuple(fields) = &**expr {
                    fields.len() >= 2
                        && fields.iter().all(atom)
                        && !list.is_empty()
                        && list.iter().all(|row| {
                            matches!(row, Expr::Tuple(values)
                            if values.len() == fields.len() && values.iter().all(atom))
                        })
                } else {
                    atom(expr) && !list.is_empty() && list.iter().all(atom)
                };
                if !valid {
                    return false;
                }
            }
            Expr::Like { expr, pattern, .. } => {
                pending.push(expr);
                pending.push(pattern);
            }
            Expr::Exists { subquery, .. } => {
                if !read_query(subquery, depth + 1) {
                    return false;
                }
            }
            Expr::Function(function) => {
                if let Some(argument) = count_argument(function) {
                    if let Some(argument) = argument {
                        pending.push(argument);
                    }
                    continue;
                }
                let Some(window) = row_number_window(function) else {
                    return false;
                };
                pending.extend(&window.partition_by);
                for order in &window.order_by {
                    if order.with_fill.is_some() {
                        return false;
                    }
                    pending.push(&order.expr);
                }
            }
            _ if atom(expr) => {}
            _ => return false,
        }
    }
    true
}

fn count_argument(function: &Function) -> Option<Option<&Expr>> {
    if !function.name.to_string().eq_ignore_ascii_case("count")
        || function.uses_odbc_syntax
        || !matches!(function.parameters, FunctionArguments::None)
        || function.filter.is_some()
        || function.null_treatment.is_some()
        || !function.within_group.is_empty()
        || function.over.is_some()
    {
        return None;
    }
    let FunctionArguments::List(args) = &function.args else {
        return None;
    };
    if !args.clauses.is_empty() {
        return None;
    }
    match args.args.as_slice() {
        [FunctionArg::Unnamed(FunctionArgExpr::Expr(expr))] => Some(Some(expr)),
        [FunctionArg::Unnamed(FunctionArgExpr::Wildcard)] if args.duplicate_treatment.is_none() => {
            Some(None)
        }
        _ => None,
    }
}

fn row_number_window(function: &Function) -> Option<&WindowSpec> {
    // Recognize only the unqualified builtin with no arguments or extensions.
    // User functions and side effects inside OVER never inherit this proof.
    if !function.name.to_string().eq_ignore_ascii_case("row_number")
        || function.uses_odbc_syntax
        || !matches!(function.parameters, FunctionArguments::None)
        || function.filter.is_some()
        || function.null_treatment.is_some()
        || !function.within_group.is_empty()
    {
        return None;
    }
    let FunctionArguments::List(args) = &function.args else {
        return None;
    };
    if !args.args.is_empty() || !args.clauses.is_empty() || args.duplicate_treatment.is_some() {
        return None;
    }
    let Some(WindowType::WindowSpec(window)) = &function.over else {
        return None;
    };
    (window.window_name.is_none() && window.window_frame.is_none()).then_some(window)
}
