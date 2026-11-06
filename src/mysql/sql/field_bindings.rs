//! Resolve direct SQL value occurrences to physical columns without changing SQL.
//! Indexed parser placeholders retain our lexer's exact scalar and bind identity.
use super::{Token, render_with_slots};
use sqlparser::{
    ast::{
        Assignment, AssignmentTarget, BinaryOperator, Expr, FromTable, ObjectName, SelectItem,
        SetExpr, Statement, TableFactor, TableObject, TableWithJoins, Value, visit_expressions,
    },
    dialect::MySqlDialect,
    parser::Parser,
};
use std::{collections::BTreeMap, ops::ControlFlow, sync::Arc};
mod cache;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldIdentity {
    pub database: Option<String>,
    pub table: String,
    pub column: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldBinding {
    pub token_index: usize,
    pub field: FieldIdentity,
}

#[derive(Debug, Clone)]
struct Relation {
    database: Option<String>,
    table: String,
    alias: Option<String>,
}

fn name(name: &ObjectName) -> Option<Vec<String>> {
    name.0
        .iter()
        .map(|p| Some(p.as_ident()?.value.clone()))
        .collect()
}

fn relation(object: &ObjectName, alias: Option<String>) -> Option<Relation> {
    let parts = name(object)?;
    let (database, table) = match parts.as_slice() {
        [table] => (None, table.clone()),
        [database, table] => (Some(database.clone()), table.clone()),
        _ => return None,
    };
    Some(Relation {
        database,
        table,
        alias,
    })
}

fn relations(tables: &[TableWithJoins]) -> Option<Vec<Relation>> {
    tables
        .iter()
        .flat_map(|t| std::iter::once(&t.relation).chain(t.joins.iter().map(|j| &j.relation)))
        .map(|table| {
            let TableFactor::Table {
                name,
                alias,
                args: None,
                ..
            } = table
            else {
                return None;
            };
            relation(name, alias.as_ref().map(|a| a.name.value.clone()))
        })
        .collect()
}

fn field(parts: &[String], tables: &[Relation], database: Option<&str>) -> Option<FieldIdentity> {
    let column = parts.last()?.clone();
    let candidates = tables
        .iter()
        .filter(|table| match parts {
            [_] => true,
            [qualifier, _] => table.alias.as_ref().unwrap_or(&table.table) == qualifier,
            [schema, qualifier, _] => {
                table.alias.is_none()
                    && &table.table == qualifier
                    && table.database.as_deref().or(database) == Some(schema.as_str())
            }
            _ => false,
        })
        .collect::<Vec<_>>();
    let [table] = candidates.as_slice() else {
        return None;
    };
    Some(FieldIdentity {
        database: table
            .database
            .clone()
            .or_else(|| database.map(str::to_owned)),
        table: table.table.clone(),
        column,
    })
}

fn column(expr: &Expr, tables: &[Relation], database: Option<&str>) -> Option<FieldIdentity> {
    match expr {
        Expr::Identifier(id) => field(std::slice::from_ref(&id.value), tables, database),
        Expr::CompoundIdentifier(ids) => field(
            &ids.iter().map(|i| i.value.clone()).collect::<Vec<_>>(),
            tables,
            database,
        ),
        Expr::Nested(expr) => column(expr, tables, database),
        _ => None,
    }
}

fn slot(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::Value(value) => match &value.value {
            Value::Placeholder(slot) => slot.strip_prefix('?')?.parse().ok(),
            _ => None,
        },
        Expr::Nested(expr) => slot(expr),
        _ => None,
    }
}

fn shape(tokens: &[Token]) -> Option<String> {
    if tokens.len() > super::bounds::MAX_TOKENS || tokens.iter().any(|t| t.is(";")) {
        return None;
    }
    Some(render_with_slots(tokens, |index, token| {
        // NULL is a direct value except in the IS [NOT] NULL grammar.
        // Replacing that predicate keyword would make otherwise supported
        // statements unparsable and hide unrelated selected assignments.
        let null_predicate = *token == Token::Null
            && (index >= 1 && tokens[index - 1].is("is")
                || index >= 2 && tokens[index - 2].is("is") && tokens[index - 1].is("not"));
        matches!(
            token,
            Token::Number(_) | Token::Bytes(_) | Token::Placeholder
        ) || *token == Token::Null && !null_predicate
    }))
}

fn parse(shape: &str) -> Option<Statement> {
    let mut statements = Parser::new(&MySqlDialect {})
        .with_recursion_limit(64)
        .try_with_sql(shape)
        .ok()?
        .parse_statements()
        .ok()?;
    if statements.len() != 1 {
        return None;
    }
    let statement = statements.pop()?;
    // Nested queries need their own relation scope. Never borrow outer aliases.
    let nested = visit_expressions(&statement, |expr| {
        if matches!(
            expr,
            Expr::Subquery(_) | Expr::InSubquery { .. } | Expr::Exists { .. }
        ) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
    if nested.is_break() {
        return None;
    }
    Some(statement)
}

fn statement_tables(statement: &Statement) -> Option<Vec<Relation>> {
    match statement {
        Statement::Query(query) if query.with.is_none() => {
            let SetExpr::Select(select) = query.body.as_ref() else {
                return None;
            };
            relations(&select.from)
        }
        Statement::Update(update) if update.from.is_none() => {
            relations(std::slice::from_ref(&update.table))
        }
        Statement::Delete(delete) if delete.using.is_none() => {
            let (FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables)) =
                &delete.from;
            relations(tables)
        }
        Statement::Insert(insert) => {
            let TableObject::TableName(name) = &insert.table else {
                return None;
            };
            Some(vec![relation(
                name,
                insert.table_alias.as_ref().map(|a| a.alias.value.clone()),
            )?])
        }
        _ => None,
    }
}

fn assigned(
    assignments: &[Assignment],
    tables: &[Relation],
    database: Option<&str>,
    output: &mut BTreeMap<usize, FieldIdentity>,
) {
    for assignment in assignments {
        if let AssignmentTarget::ColumnName(target) = &assignment.target
            && let Some(position) = slot(&assignment.value)
            && let Some(field) = name(target).and_then(|parts| field(&parts, tables, database))
        {
            output.insert(position, field);
        }
    }
}

fn resolve_statement(
    statement: &Statement,
    tables: &[Relation],
    database: Option<&str>,
) -> Option<Vec<FieldBinding>> {
    let mut output = BTreeMap::new();
    match statement {
        Statement::Update(update) => assigned(&update.assignments, tables, database, &mut output),
        Statement::Insert(insert) => {
            assigned(&insert.assignments, tables, database, &mut output);
            if let Some(source) = &insert.source {
                let SetExpr::Values(values) = source.body.as_ref() else {
                    return None;
                };
                for row in &values.rows {
                    if row.len() != insert.columns.len() {
                        return None;
                    }
                    for (target, value) in insert.columns.iter().zip(row.iter()) {
                        if let Some(position) = slot(value)
                            && let Some(field) =
                                name(target).and_then(|parts| field(&parts, tables, database))
                        {
                            output.insert(position, field);
                        }
                    }
                }
            }
            if let Some(sqlparser::ast::OnInsert::DuplicateKeyUpdate(assignments)) = &insert.on {
                assigned(assignments, tables, database, &mut output);
            }
        }
        _ => (),
    }
    let _: ControlFlow<()> = visit_expressions(statement, |expr| {
        let mut add = |column_expr: &Expr, value: &Expr| {
            if let Some(field) = column(column_expr, tables, database)
                && let Some(position) = slot(value)
            {
                output.insert(position, field);
            }
        };
        match expr {
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
            } => {
                add(left, right);
                add(right, left);
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                add(expr, low);
                add(expr, high);
            }
            Expr::InList { expr, list, .. } => {
                for value in list {
                    add(expr, value);
                }
            }
            _ => (),
        }
        ControlFlow::Continue(())
    });
    Some(
        output
            .into_iter()
            .map(|(token_index, field)| FieldBinding { token_index, field })
            .collect(),
    )
}

fn projection_statement(
    statement: &Statement,
    tables: &[Relation],
    database: Option<&str>,
) -> Option<Vec<Option<FieldIdentity>>> {
    let Statement::Query(query) = statement else {
        return None;
    };
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    select
        .projection
        .iter()
        .map(|item| match item {
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                Some(column(expr, tables, database))
            }
            _ => None,
        })
        .collect()
}

#[derive(Debug)]
pub(crate) struct FieldAnalysis {
    /// An absent observed default schema cannot resolve any unqualified relation.
    pub unresolved_database: bool,
    pub bindings: Vec<FieldBinding>,
    pub projections: Option<Vec<Option<FieldIdentity>>>,
    projection_labels: Option<Vec<String>>,
}

impl FieldAnalysis {
    /// Bindings are emitted in token order from the resolver's ordered map.
    pub(crate) fn at_token(&self, position: usize) -> Option<&FieldIdentity> {
        self.bindings
            .binary_search_by_key(&position, |binding| binding.token_index)
            .ok()
            .map(|index| &self.bindings[index].field)
    }
}

fn analyze_shape(shape: &str, database: Option<&str>) -> Option<FieldAnalysis> {
    let statement = parse(shape)?;
    let tables = statement_tables(&statement)?;
    let bindings = resolve_statement(&statement, &tables, database)?;
    Some(FieldAnalysis {
        unresolved_database: database.is_none()
            && tables.iter().any(|table| table.database.is_none()),
        bindings,
        projections: projection_statement(&statement, &tables, database),
        projection_labels: match &statement {
            Statement::Query(query) => match query.body.as_ref() {
                SetExpr::Select(select) => select
                    .projection
                    .iter()
                    .map(|item| match item {
                        SelectItem::ExprWithAlias { alias, .. } => Some(alias.value.clone()),
                        SelectItem::UnnamedExpr(expr) => {
                            column(expr, &tables, database).map(|field| field.column)
                        }
                        _ => None,
                    })
                    .collect(),
                _ => None,
            },
            _ => None,
        },
    })
}

/// Cache only immutable statement shape and physical field positions. Literal
/// values, bound parameters, clocks, rules and candidate state never enter it.
pub(crate) fn analyze(tokens: &[Token], database: Option<&str>) -> Option<Arc<FieldAnalysis>> {
    cache::get(shape(tokens)?, database)
}

/// Direct values associated with a proved physical column. Unknown expressions
/// and ambiguous unqualified JOIN columns grant no permission.
pub(crate) fn resolve(tokens: &[Token], database: Option<&str>) -> Option<Vec<FieldBinding>> {
    Some(analyze(tokens, database)?.bindings.clone())
}

pub(crate) fn projection_columns(
    tokens: &[Token],
    database: Option<&str>,
) -> Option<Vec<(String, Option<FieldIdentity>)>> {
    let analysis = analyze(tokens, database)?;
    Some(
        analysis
            .projection_labels
            .as_ref()?
            .iter()
            .cloned()
            .zip(analysis.projections.as_ref()?.iter().cloned())
            .collect(),
    )
}

#[cfg(test)]
mod tests;
