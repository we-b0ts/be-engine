//! Bounded MySQL predicate equivalence. sqlparser owns grammar; this module
//! admits only pure predicates and retains the rest of each query verbatim.
use super::MAX_SQL_TOKENS;
use crate::mysql::sql::{Token, render};
use sqlparser::{
    ast::{BinaryOperator, Distinct, Expr, SelectItem, SetExpr, Statement, TableFactor, Value},
    dialect::MySqlDialect,
    parser::Parser,
    tokenizer::Token as ParserToken,
};

mod in_list;

#[derive(Clone, Debug)]
pub(super) struct Template {
    start: usize,
    end: usize,
    predicate: Predicate,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Operand {
    Column(Vec<String>),
    Slot(usize),
    Value(Token),
    Tuple(Vec<Operand>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Predicate {
    Compare(Operand, BinaryOperator, Operand),
    IsNull(Operand, bool),
    TruthTest(Operand, TruthValue, bool),
    Between(Operand, bool, Operand, Operand),
    In(Operand, bool, Vec<Operand>),
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TruthValue {
    True,
    False,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Key {
    prefix: Vec<Token>,
    predicate: Predicate,
    suffix: Vec<Token>,
}

impl Template {
    pub(super) fn parse(tokens: &[Token], whole_query: bool) -> Option<Self> {
        if tokens.len() > MAX_SQL_TOKENS {
            return None;
        }
        let mut depth = 0_usize;
        let mut start = None;
        let mut end = tokens.len();
        for (i, token) in tokens.iter().enumerate() {
            if token.is("(") {
                depth += 1;
                if depth > 32 {
                    return None;
                }
            } else if token.is(")") {
                depth = depth.checked_sub(1)?;
            } else if depth == 0 {
                if token.is("where") {
                    if start.replace(i + 1).is_some() {
                        return None;
                    }
                } else if start.is_some() && (token.is("order") || token.is("limit")) {
                    end = end.min(i);
                }
            }
        }
        if depth != 0 {
            return None;
        }
        let start = start?;
        // Stable indexed slots preserve our existing MySQL literal decoding,
        // exact decimals, binary bytes and original placeholder positions. No
        // parameter is interpolated into executable SQL. NULL stays a keyword
        // so that IS NULL is parsed as its own operator.
        let parser_tokens = tokens
            .iter()
            .enumerate()
            .map(|(i, token)| match token {
                Token::Number(_) | Token::Bytes(_) | Token::Placeholder => {
                    Token::Symbol(format!("?{i}"))
                }
                _ => token.clone(),
            })
            .collect::<Vec<_>>();
        let dialect = MySqlDialect {};
        let expr = if whole_query {
            if tokens.iter().any(|t| {
                [
                    "group", "having", "union", "into", "for", "lock", "@", "@@", ":=", "||", "&&",
                ]
                .iter()
                .any(|s| t.is(s))
            }) || tokens.iter().filter(|t| t.is("select")).count() != 1
            {
                return None;
            }
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
            if query.with.is_some() || !query.locks.is_empty() {
                return None;
            }
            let SetExpr::Select(select) = *query.body else {
                return None;
            };
            if let Some(distinct) = &select.distinct
                && !matches!(distinct, Distinct::All)
                && (!matches!(distinct, Distinct::Distinct)
                    || select.projection.iter().any(|item| match item {
                        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                            !matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_))
                        }
                        _ => true,
                    }))
            {
                return None;
            }
            // Direct-table JOINs remain part of the exact prefix. Only the
            // proven-pure WHERE predicate below is normalized, so JOIN kind,
            // relation and ON conditions cannot acquire compatibility here.
            if select.from.len() != 1
                || !matches!(
                    select.from[0].relation,
                    TableFactor::Table { args: None, .. }
                )
                || select.from[0]
                    .joins
                    .iter()
                    .any(|join| !matches!(&join.relation, TableFactor::Table { args: None, .. }))
                || select.projection.iter().any(|item| match item {
                    SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                        !matches!(
                            expr,
                            Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_)
                        ) && !expr.to_string().eq_ignore_ascii_case("count(*)")
                    }
                    SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => false,
                    _ => true,
                })
            {
                return None;
            }
            // Keep computed sorting, including FIELD and side-effectful
            // functions, off this compatibility path.
            if tokens[end..].windows(2).any(|pair| pair[1].is("(")) {
                return None;
            }
            let selection = select.selection?;
            // A permissive dialect parser may recognize vendor-specific tail
            // clauses. Prove that the entire extracted WHERE range belongs to
            // this predicate instead of silently dropping such a clause.
            let mut predicate_parser = Parser::new(&dialect)
                .with_recursion_limit(64)
                .try_with_sql(&render(&parser_tokens[start..end]))
                .ok()?;
            if predicate_parser.parse_expr().ok()? != selection
                || predicate_parser.next_token().token != ParserToken::EOF
            {
                return None;
            }
            selection
        } else {
            let mut parser = Parser::new(&dialect)
                .with_recursion_limit(64)
                .try_with_sql(&render(&parser_tokens[start..end]))
                .ok()?;
            let expr = parser.parse_expr().ok()?;
            if parser.next_token().token != ParserToken::EOF {
                return None;
            }
            expr
        };
        Some(Self {
            start,
            end,
            predicate: predicate(&expr, 0)?,
        })
    }

    pub(super) fn bind(&self, tokens: &[Token]) -> Option<Key> {
        Some(Key {
            prefix: tokens.get(..self.start)?.to_vec(),
            predicate: self.predicate.bind(tokens)?,
            suffix: tokens.get(self.end..)?.to_vec(),
        })
    }
}

fn operand(expr: &Expr) -> Option<Operand> {
    match expr {
        Expr::Identifier(id) => Some(Operand::Column(vec![id.value.clone()])),
        Expr::CompoundIdentifier(ids) => Some(Operand::Column(
            ids.iter().map(|id| id.value.clone()).collect(),
        )),
        Expr::Value(value) => match &value.value {
            Value::Placeholder(slot) => Some(Operand::Slot(slot.strip_prefix('?')?.parse().ok()?)),
            Value::Null => Some(Operand::Value(Token::Null)),
            _ => None,
        },
        _ => None,
    }
}

fn predicate(expr: &Expr, depth: usize) -> Option<Predicate> {
    if depth > 64 {
        return None;
    }
    Some(match expr {
        Expr::Nested(expr) => return predicate(expr, depth + 1),
        Expr::BinaryOp {
            left,
            op: op @ (BinaryOperator::And | BinaryOperator::Or),
            right,
        } => {
            let mut terms = Vec::new();
            // sqlparser represents a flat group as a left-associated tree.
            // Count nesting of different operators, not the number of terms.
            let mut pending = vec![right.as_ref(), left.as_ref()];
            while let Some(expr) = pending.pop() {
                match expr {
                    Expr::Nested(expr) => pending.push(expr),
                    Expr::BinaryOp {
                        left,
                        op: child_op,
                        right,
                    } if child_op == op => {
                        pending.push(right);
                        pending.push(left);
                    }
                    expr => terms.push(predicate(expr, depth + 1)?),
                }
            }
            if *op == BinaryOperator::And {
                Predicate::And(terms)
            } else {
                Predicate::Or(terms)
            }
        }
        Expr::BinaryOp { left, op, right }
            if matches!(
                op,
                BinaryOperator::Eq
                    | BinaryOperator::NotEq
                    | BinaryOperator::Lt
                    | BinaryOperator::LtEq
                    | BinaryOperator::Gt
                    | BinaryOperator::GtEq
                    | BinaryOperator::Spaceship
            ) =>
        {
            Predicate::Compare(operand(left)?, op.clone(), operand(right)?)
        }
        Expr::IsNull(expr) => Predicate::IsNull(operand(expr)?, false),
        Expr::IsNotNull(expr) => Predicate::IsNull(operand(expr)?, true),
        Expr::IsTrue(expr) => Predicate::TruthTest(operand(expr)?, TruthValue::True, false),
        Expr::IsNotTrue(expr) => Predicate::TruthTest(operand(expr)?, TruthValue::True, true),
        Expr::IsFalse(expr) => Predicate::TruthTest(operand(expr)?, TruthValue::False, false),
        Expr::IsNotFalse(expr) => Predicate::TruthTest(operand(expr)?, TruthValue::False, true),
        Expr::IsUnknown(expr) => Predicate::TruthTest(operand(expr)?, TruthValue::Unknown, false),
        Expr::IsNotUnknown(expr) => Predicate::TruthTest(operand(expr)?, TruthValue::Unknown, true),
        Expr::Between {
            expr,
            negated,
            low,
            high,
        } => Predicate::Between(operand(expr)?, *negated, operand(low)?, operand(high)?),
        Expr::InList {
            expr,
            list,
            negated,
        } if !list.is_empty() => {
            let (left, values) = in_list::parse(expr, list)?;
            Predicate::In(left, *negated, values)
        }
        _ => return None,
    })
}

impl Operand {
    fn bind(&self, tokens: &[Token]) -> Option<Self> {
        match self {
            Self::Slot(index) => {
                let value = tokens.get(*index)?;
                (value.is_value() || *value == Token::Placeholder)
                    .then(|| Self::Value(value.clone()))
            }
            Self::Tuple(fields) => Some(Self::Tuple(
                fields
                    .iter()
                    .map(|field| field.bind(tokens))
                    .collect::<Option<_>>()?,
            )),
            value => Some(value.clone()),
        }
    }

    fn metadata_matches(&self, recorded: &Self) -> bool {
        match (self, recorded) {
            (Self::Tuple(actual), Self::Tuple(recorded)) => {
                actual.len() == recorded.len()
                    && actual
                        .iter()
                        .zip(recorded)
                        .all(|(a, r)| a.metadata_matches(r))
            }
            _ => {
                self == recorded
                    || matches!(self, Self::Value(Token::Placeholder))
                        && matches!(recorded, Self::Value(_))
            }
        }
    }
}

impl Predicate {
    fn bind(&self, tokens: &[Token]) -> Option<Self> {
        Some(match self {
            Self::Compare(a, op, b) => Self::Compare(a.bind(tokens)?, op.clone(), b.bind(tokens)?),
            Self::IsNull(a, not) => Self::IsNull(a.bind(tokens)?, *not),
            Self::TruthTest(a, truth, not) => Self::TruthTest(a.bind(tokens)?, *truth, *not),
            Self::Between(a, not, b, c) => {
                Self::Between(a.bind(tokens)?, *not, b.bind(tokens)?, c.bind(tokens)?)
            }
            Self::In(a, not, values) => {
                Self::In(a.bind(tokens)?, *not, in_list::bind(values, tokens)?)
            }
            Self::And(terms) | Self::Or(terms) => {
                let mut terms = terms
                    .iter()
                    .map(|v| v.bind(tokens))
                    .collect::<Option<Vec<_>>>()?;
                terms.sort();
                if matches!(self, Self::And(_)) {
                    Self::And(terms)
                } else {
                    Self::Or(terms)
                }
            }
        })
    }

    fn metadata_matches(&self, recorded: &Self, budget: &mut usize) -> bool {
        // Alternating AND/OR trees can multiply candidate comparisons across
        // levels. Share a bound across the whole PREPARE comparison.
        let Some(remaining) = budget.checked_sub(1) else {
            return false;
        };
        *budget = remaining;
        match (self, recorded) {
            (Self::Compare(a, op, b), Self::Compare(x, rop, y)) => {
                op == rop && a.metadata_matches(x) && b.metadata_matches(y)
            }
            (Self::IsNull(a, not), Self::IsNull(x, rnot)) => not == rnot && a.metadata_matches(x),
            (Self::TruthTest(a, truth, not), Self::TruthTest(x, rtruth, rnot)) => {
                truth == rtruth && not == rnot && a.metadata_matches(x)
            }
            (Self::Between(a, not, b, c), Self::Between(x, rnot, y, z)) => {
                not == rnot
                    && a.metadata_matches(x)
                    && b.metadata_matches(y)
                    && c.metadata_matches(z)
            }
            (Self::In(a, not, values), Self::In(x, rnot, recorded)) => {
                not == rnot && a.metadata_matches(x) && in_list::metadata_matches(values, recorded)
            }
            (Self::And(terms), Self::And(recorded)) | (Self::Or(terms), Self::Or(recorded)) => {
                if terms.len() != recorded.len() {
                    return false;
                }
                if let Some(template) = terms.first()
                    && terms.iter().all(|term| term == template)
                {
                    // Identical parameter templates have identical candidate
                    // sets. Every source branch must satisfy that template;
                    // equal cardinality then proves a one-to-one assignment.
                    // Preserve fixed literals and duplicates without N² work.
                    recorded
                        .iter()
                        .all(|r| template.metadata_matches(r, budget))
                } else {
                    injective_metadata(terms, recorded, |a, r| a.metadata_matches(r, budget))
                }
            }
            _ => false,
        }
    }
}

impl Key {
    pub(super) fn metadata_matches(&self, recorded: &Self) -> bool {
        fn same(actual: &[Token], recorded: &[Token]) -> bool {
            actual.len() == recorded.len()
                && actual
                    .iter()
                    .zip(recorded)
                    .all(|(a, r)| a == r || *a == Token::Placeholder && r.is_value())
        }
        let mut budget = 16_384;
        same(&self.prefix, &recorded.prefix)
            && same(&self.suffix, &recorded.suffix)
            && self
                .predicate
                .metadata_matches(&recorded.predicate, &mut budget)
            && budget > 0
    }
}

// PREPARE has no actual values. Repeated fields and partially bound IN lists
// require a one-to-one assignment, not a greedy match or SQL-shape wildcard.
fn injective_metadata<T>(
    actual: &[T],
    recorded: &[T],
    mut matches: impl FnMut(&T, &T) -> bool,
) -> bool {
    if actual.len() > recorded.len()
        || actual.len() > 64
        || actual.len().saturating_mul(recorded.len()) > 4096
    {
        return false;
    }
    let edges = actual
        .iter()
        .map(|a| recorded.iter().map(|r| matches(a, r)).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    fn assign(
        a: usize,
        edges: &[Vec<bool>],
        seen: &mut [bool],
        owners: &mut [Option<usize>],
    ) -> bool {
        for r in 0..owners.len() {
            if !edges[a][r] || seen[r] {
                continue;
            }
            seen[r] = true;
            if owners[r].is_none_or(|previous| assign(previous, edges, seen, owners)) {
                owners[r] = Some(a);
                return true;
            }
        }
        false
    }
    let mut owners = vec![None; recorded.len()];
    (0..actual.len()).all(|a| assign(a, &edges, &mut vec![false; recorded.len()], &mut owners))
}
