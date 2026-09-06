//! A small SELECT allowlist for proving implicit read-only session cleanup.
//! This is an effect check, not SQL equivalence or a general transaction model.
use crate::mysql::sql;
use sqlparser::{
    ast::{
        BinaryOperator, Expr, GroupByExpr, LimitClause, OrderByKind, SelectItem, SetExpr,
        Statement, TableFactor, UnaryOperator,
    },
    dialect::MySqlDialect,
    parser::Parser,
};

pub(super) fn plain_select(sql: &str) -> bool {
    if sql.len() > 64 * 1024 {
        return false;
    }
    // The shared scanner rejects executable comments/hints and bounds the
    // parser input. Parse original spelling so quoted identifiers stay quoted.
    let Some(tokens) = sql::tokens(sql).filter(|tokens| tokens.len() <= 4096) else {
        return false;
    };
    if tokens
        .iter()
        .any(|t| ["@", "@@", ":=", "||", "&&"].iter().any(|s| t.is(s)))
    {
        return false;
    }
    let Ok(mut parser) = Parser::new(&MySqlDialect {})
        .with_recursion_limit(64)
        .try_with_sql(sql)
    else {
        return false;
    };
    let Ok(statements) = parser.parse_statements() else {
        return false;
    };
    let [Statement::Query(query)] = statements.as_slice() else {
        return false;
    };
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
        || select.distinct.is_some()
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
        || select.having.is_some()
        || !select.named_window.is_empty()
        || select.qualify.is_some()
        || select.value_table_mode.is_some()
        || !matches!(&select.group_by, GroupByExpr::Expressions(exprs, modifiers)
            if exprs.is_empty() && modifiers.is_empty())
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
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => atom(expr),
            SelectItem::Wildcard(options) | SelectItem::QualifiedWildcard(_, options) => {
                *options == Default::default()
            }
            _ => false,
        })
        || !select
            .selection
            .as_ref()
            .is_none_or(|expr| predicate(expr, 0))
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
                .all(|expr| atom(&expr.expr) && expr.with_fill.is_none())
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
                && limit.as_ref().is_none_or(atom)
                && offset.as_ref().is_none_or(|offset| atom(&offset.value))
        }
        Some(LimitClause::OffsetCommaLimit { offset, limit }) => atom(offset) && atom(limit),
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

fn predicate(expr: &Expr, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    match expr {
        Expr::Nested(expr)
        | Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => predicate(expr, depth + 1),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And | BinaryOperator::Or,
            right,
        } => predicate(left, depth + 1) && predicate(right, depth + 1),
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
        } => atom(left) && atom(right),
        Expr::IsNull(expr) | Expr::IsNotNull(expr) => atom(expr),
        Expr::Between {
            expr, low, high, ..
        } => atom(expr) && atom(low) && atom(high),
        Expr::InList { expr, list, .. } => atom(expr) && !list.is_empty() && list.iter().all(atom),
        Expr::Like { expr, pattern, .. } => atom(expr) && atom(pattern),
        _ => atom(expr),
    }
}
