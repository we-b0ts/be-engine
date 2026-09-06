//! Resolve direct-column SELECT projections without changing query semantics.
use super::{Token, tokens_with_spans};

#[derive(Clone, Debug)]
pub(crate) struct DirectColumn {
    pub name: Option<String>,
    pub expression: Vec<Token>,
    pub label: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DirectSelect {
    pub columns: Vec<DirectColumn>,
    pub table: String,
    pub table_alias: Option<String>,
    /// Physical FROM identity and remaining clauses, with bound aliases resolved.
    pub body: Vec<Token>,
}

impl DirectSelect {
    pub(crate) fn parse(raw: &str, sql: &[Token]) -> Option<Self> {
        let (original, spans) = tokens_with_spans(raw)?;
        if original.len() != sql.len() {
            return None;
        }
        if !sql.first()?.is("select") || sql.iter().filter(|t| t.is("select")).count() != 1 {
            return None;
        }
        // These forms can make column removal or reordering change row semantics.
        if sql.iter().any(|t| {
            [
                "distinct", "group", "having", "union", "join", "into", "for", "lock", "@", "@@",
                ":=",
            ]
            .iter()
            .any(|word| t.is(word))
        }) {
            return None;
        }
        if let Token::Word(word) = sql.get(1)?
            && [
                "all",
                "distinctrow",
                "high_priority",
                "straight_join",
                "sql_small_result",
                "sql_big_result",
                "sql_buffer_result",
                "sql_no_cache",
                "sql_cache",
                "sql_calc_found_rows",
            ]
            .iter()
            .any(|flag| word.eq_ignore_ascii_case(flag))
        {
            return None;
        }
        let from = sql.iter().position(|t| t.is("from")).unwrap_or(sql.len());
        if sql.iter().filter(|t| t.is("from")).count() > 1 {
            return None;
        }
        let (relation, used) = if from == sql.len() {
            (Vec::new(), 0)
        } else {
            identifier_path(&sql[from + 1..])?
        };
        if relation.len() > 2 {
            return None;
        }
        let mut tail_start = (from + 1 + used).min(sql.len());
        let mut alias = None;
        if sql.get(tail_start).is_some_and(|t| t.is("as")) {
            alias = Some(identifier(sql.get(tail_start + 1)?)?.to_string());
            tail_start += 2;
        } else if let Some(token) = sql.get(tail_start)
            && !clause(token)
        {
            alias = Some(identifier(token)?.to_string());
            tail_start += 1;
        }
        let mut select = Self {
            columns: Vec::new(),
            table: relation.last().cloned().unwrap_or_default(),
            table_alias: alias,
            body: Vec::new(),
        };
        // The relation is compared exactly; table aliases are resolved locally.
        select.body = sql[from..(from + 1 + used).min(sql.len())].to_vec();
        let mut item_start = 1;
        for item in sql[1..from].split(|t| t.is(",")) {
            let (field, used) = if matches!(item.first(), Some(Token::Number(_))) {
                // A projection literal carries a result type as well as a value.
                // Keep integer constants bounded here; decimal/exponent forms and
                // bound output parameters need their own metadata adaptation.
                let literal = &raw[spans[item_start].clone()];
                if !literal.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                (None, 1)
            } else if item.get(..4).is_some_and(|tokens| {
                tokens[0].is("count") && tokens[1].is("(") && tokens[2].is("*") && tokens[3].is(")")
            }) {
                (None, 4)
            } else {
                if relation.is_empty() {
                    return None;
                }
                let (path, used) = identifier_path(item)?;
                if path.len() == 1 && bare_expression(item.first()?) {
                    return None;
                }
                (Some(select.field(&relation, &path)?), used)
            };
            let label = match &item[used..] {
                [] => field.clone().unwrap_or_else(|| {
                    raw[spans[item_start].start..spans[item_start + used - 1].end].to_string()
                }),
                [label] => output_label(label)?,
                [as_token, label] if as_token.is("as") => output_label(label)?,
                _ => return None,
            };
            select.columns.push(DirectColumn {
                name: field,
                expression: item[..used].to_vec(),
                label,
            });
            item_start += item.len() + 1;
        }
        if select.columns.is_empty() {
            return None;
        }
        // Bare fields mixed with an aggregate require GROUP BY semantics, which
        // remain on the existing exact matching path.
        if select
            .columns
            .iter()
            .any(|c| c.name.is_none() && c.expression.first().is_some_and(|t| t.is("count")))
            && select.columns.iter().any(|c| c.name.is_some())
        {
            return None;
        }
        let tail = &sql[tail_start..];
        if !tail.is_empty() && !clause(&tail[0]) {
            return None;
        }
        let order = tail.iter().position(|t| t.is("order"));
        let limit = tail.iter().position(|t| t.is("limit"));
        if order.zip(limit).is_some_and(|(order, limit)| order > limit) {
            return None;
        }
        let where_end = order.or(limit).unwrap_or(tail.len());
        if where_end > 0 && (!tail[0].is("where") || where_end == 1) {
            return None;
        }
        select
            .body
            .extend(select.resolve_qualifiers(&relation, &tail[..where_end]));
        if let Some(start) = order {
            if !tail.get(start + 1)?.is("by") {
                return None;
            }
            select
                .body
                .extend([tail[start].clone(), tail[start + 1].clone()]);
            let terms = &tail[start + 2..limit.unwrap_or(tail.len())];
            let mut term_start = tail_start + start + 2;
            for (i, term) in terms.split(|t| t.is(",")).enumerate() {
                if i > 0 {
                    select.body.push(Token::Symbol(",".into()));
                }
                let raw_first = &raw[spans.get(term_start)?.clone()];
                let (field, direction) = select.order_field(&relation, term, raw_first)?;
                select.body.push(Token::Identifier(field));
                select.body.extend(direction.cloned());
                term_start += term.len() + 1;
            }
        }
        if let Some(start) = limit {
            // Retain pagination tokens and values exactly, including placeholders.
            select.body.extend_from_slice(&tail[start..]);
        }
        Some(select)
    }

    fn field(&self, relation: &[String], path: &[String]) -> Option<String> {
        let (name, qualifier) = path.split_last()?;
        let valid = qualifier.is_empty()
            || match &self.table_alias {
                Some(alias) => qualifier == std::slice::from_ref(alias),
                None => {
                    qualifier == std::slice::from_ref(relation.last()?) || qualifier == relation
                }
            };
        valid.then(|| name.clone())
    }

    fn order_field<'a>(
        &self,
        relation: &[String],
        term: &'a [Token],
        raw_first: &str,
    ) -> Option<(String, Option<&'a Token>)> {
        let (expression, direction) = if term.last().is_some_and(|t| t.is("asc") || t.is("desc")) {
            (&term[..term.len() - 1], term.last())
        } else {
            (term, None)
        };
        if let [Token::Number(_)] = expression {
            // Only a literal integer is a column position. A decimal expression
            // or an executed bound parameter with value 1 is a constant sort key.
            if !raw_first.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let index = raw_first.parse::<usize>().ok()?.checked_sub(1)?;
            return Some((self.columns.get(index)?.name.clone()?, direction));
        }
        let (path, used) = identifier_path(expression)?;
        if used != expression.len() {
            return None;
        }
        let mut field = self.field(relation, &path)?;
        if path.len() == 1 {
            let mut aliases = self
                .columns
                .iter()
                .filter(|c| c.label.eq_ignore_ascii_case(&field));
            if let Some(column) = aliases.next() {
                if aliases.next().is_some() {
                    return None;
                }
                field = column.name.clone()?;
            }
        }
        Some((field, direction))
    }

    fn resolve_qualifiers(&self, relation: &[String], tokens: &[Token]) -> Vec<Token> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < tokens.len() {
            if let Some((path, used)) = identifier_path(&tokens[i..]) {
                if path.len() > 1
                    && !tokens.get(i + used).is_some_and(|t| t.is("("))
                    && self.field(relation, &path).is_some()
                {
                    out.push(tokens[i + used - 1].clone());
                } else {
                    out.extend_from_slice(&tokens[i..i + used]);
                }
                i += used;
                continue;
            }
            out.push(tokens[i].clone());
            i += 1;
        }
        out
    }
}

fn bare_expression(token: &Token) -> bool {
    matches!(token, Token::Word(word) if [
        "current_date", "current_time", "current_timestamp", "current_user",
        "localtime", "localtimestamp", "utc_date", "utc_time", "utc_timestamp",
    ].iter().any(|expression| word.eq_ignore_ascii_case(expression)))
}

fn clause(token: &Token) -> bool {
    ["where", "order", "limit"].iter().any(|s| token.is(s))
}

fn identifier(token: &Token) -> Option<&str> {
    match token {
        Token::Word(value) | Token::Identifier(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

fn output_label(token: &Token) -> Option<String> {
    let label = match token {
        Token::Bytes(value) => std::str::from_utf8(value).ok()?,
        _ => identifier(token)?,
    };
    (label.len() <= 256).then(|| label.to_string())
}

fn identifier_path(tokens: &[Token]) -> Option<(Vec<String>, usize)> {
    let mut path = vec![identifier(tokens.first()?)?.to_string()];
    let mut used = 1;
    while tokens.get(used).is_some_and(|t| t.is(".")) {
        path.push(identifier(tokens.get(used + 1)?)?.to_string());
        used += 2;
    }
    Some((path, used))
}
