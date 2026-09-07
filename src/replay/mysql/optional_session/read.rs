//! Bounded SQL effect analysis, independent of predicate equivalence.
//! This is an effect check, not SQL equivalence or a general transaction model.
use crate::mysql::sql;
use sqlparser::{
    ast::{
        BinaryOperator, Distinct, Expr, GroupByExpr, LimitClause, OrderByKind, SelectItem, SetExpr,
        Statement, TableFactor, UnaryOperator,
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
    if read_query(query) {
        Effect::ReadOnly
    } else {
        Effect::Unknown
    }
}

fn read_query(query: &sqlparser::ast::Query) -> bool {
    if query.with.is_some()
        || query.fetch.is_some()
        || !query.locks.is_empty()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
    {
        return false;
    }
    let SetExpr::Select(select) = &*query.body else {
        return false;
    };
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
        || select.from.len() != 1
    {
        return false;
    }
    let table = &select.from[0];
    if !table.joins.is_empty() {
        return false;
    }
    match &table.relation {
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
        } if with_hints.is_empty() && partitions.is_empty() && index_hints.is_empty() => {}
        _ => return false,
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

fn atom(expr: &Expr) -> bool {
    // No functions, subqueries, session-variable reads/assignments or calls
    // hidden inside ordering/pagination/projection expressions.
    matches!(
        expr,
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_)
    )
}

fn pure(expr: &Expr) -> bool {
    expression(expr, 0)
}

fn expression(expr: &Expr, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    match expr {
        Expr::Nested(expr)
        | Expr::UnaryOp {
            op: UnaryOperator::Not | UnaryOperator::Plus | UnaryOperator::Minus,
            expr,
        } => expression(expr, depth + 1),
        Expr::BinaryOp {
            left,
            op:
                BinaryOperator::And
                | BinaryOperator::Or
                | BinaryOperator::Plus
                | BinaryOperator::Minus
                | BinaryOperator::Multiply
                | BinaryOperator::Divide
                | BinaryOperator::Modulo,
            right,
        } => expression(left, depth + 1) && expression(right, depth + 1),
        Expr::BinaryOp {
            left,
            op:
                BinaryOperator::Eq
                | BinaryOperator::NotEq
                | BinaryOperator::Lt
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::GtEq
                | BinaryOperator::Spaceship,
            right,
        } => expression(left, depth + 1) && expression(right, depth + 1),
        Expr::IsNull(expr) | Expr::IsNotNull(expr) => expression(expr, depth + 1),
        Expr::Between {
            expr, low, high, ..
        } => {
            expression(expr, depth + 1) && expression(low, depth + 1) && expression(high, depth + 1)
        }
        Expr::InList { expr, list, .. } => {
            if let Expr::Tuple(fields) = &**expr {
                fields.len() >= 2
                    && fields.iter().all(atom)
                    && !list.is_empty()
                    && list.iter().all(|row| {
                        matches!(row, Expr::Tuple(values)
                        if values.len() == fields.len() && values.iter().all(atom))
                    })
            } else {
                atom(expr) && !list.is_empty() && list.iter().all(atom)
            }
        }
        Expr::Like { expr, pattern, .. } => {
            expression(expr, depth + 1) && expression(pattern, depth + 1)
        }
        _ => atom(expr),
    }
}
