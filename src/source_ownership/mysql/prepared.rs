//! Per-classification SQL preparation; complete pairs share compact match results.
use super::{MARKER, boundary_tokens, positive, row_tokens, successful, tokens};
use crate::config::mysql_tables::TableMatcher;
use crate::mysql::sql::{self, Token};
use crate::policy::{AsyncOwnershipRequest, Resource};
use crate::source_ownership::{Rule, projection::resource_matches};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::marker::PhantomData;

type Selection = (BTreeMap<String, u64>, bool);
type Row = (String, BTreeMap<String, Token>);

pub(super) struct Pattern<'a> {
    request: &'a AsyncOwnershipRequest,
    resource: &'a Resource,
    tokens: Vec<Token>,
    table: Option<TableMatcher>,
    bindings: &'a BTreeMap<usize, String>,
    member: bool,
}

impl<'a> Pattern<'a> {
    pub fn new(request: &'a AsyncOwnershipRequest) -> Option<Self> {
        let AsyncOwnershipRequest::Mysql {
            resource,
            sql,
            tables,
            table_patterns,
            bindings,
            transaction_member,
        } = request
        else {
            return None;
        };
        Some(Self {
            request,
            resource,
            tokens: sql::bounds::statement(&sql.replace("{{table}}", MARKER))?,
            table: if sql.contains("{{table}}") {
                Some(TableMatcher::new(tables, table_patterns, None).ok()?)
            } else {
                None
            },
            bindings,
            member: *transaction_member,
        })
    }

    pub fn matches(&self, event: &Value, actual: &[Token]) -> Option<Selection> {
        if !resource_matches(self.resource, event) || self.tokens.len() != actual.len() {
            return None;
        }
        let table = self.tokens.iter().enumerate().find_map(|(index, token)| {
            if token.is(MARKER) {
                match actual.get(index)? {
                    Token::Word(value) | Token::Identifier(value) => Some(value.as_str()),
                    _ => None,
                }
            } else {
                None
            }
        });
        if self
            .table
            .as_ref()
            .is_some_and(|matcher| !table.is_some_and(|table| matcher.matches(table)))
        {
            return None;
        }
        let mut captures = BTreeMap::new();
        let mut position = 0;
        for (expected, actual) in self.tokens.iter().zip(actual) {
            if *expected == Token::Placeholder {
                if !actual.is_value() {
                    return None;
                }
                if let Some(name) = self.bindings.get(&position) {
                    let value = positive(actual)?;
                    if captures
                        .insert(name.clone(), value)
                        .is_some_and(|old| old != value)
                    {
                        return None;
                    }
                }
                position += 1;
            } else if let Some(table) = table {
                if !sql::table_template::matches_token(expected, actual, MARKER, table) {
                    return None;
                }
            } else if expected != actual {
                return None;
            }
        }
        Some((captures, self.member))
    }
}

#[derive(Default)]
pub(crate) struct Matches<'a> {
    selected: HashMap<(usize, usize), Selection>,
    facts: HashMap<usize, Facts>,
    // Address keys are valid only while these immutable inputs remain borrowed.
    source: PhantomData<(&'a [Rule<'a>], &'a [Value])>,
}

#[derive(Default)]
struct Facts {
    boundary: Option<&'static str>,
    rollback: bool,
    write: bool,
    row: Option<Row>,
}

fn event_key(event: &Value) -> usize {
    std::ptr::from_ref(event) as usize
}
fn request_key(request: &AsyncOwnershipRequest) -> usize {
    std::ptr::from_ref(request) as usize
}

impl<'a> Matches<'a> {
    pub fn new(rules: &'a [Rule<'a>], events: &'a [Value]) -> Self {
        let patterns = rules
            .iter()
            .flat_map(|rule| &rule.ownership.requests)
            .filter_map(Pattern::new)
            .collect::<Vec<_>>();
        let columns = rules
            .iter()
            .flat_map(|rule| {
                rule.ownership
                    .origin
                    .row_match
                    .keys()
                    .chain(rule.ownership.origin.bindings.values())
            })
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let mut result = Self::default();
        for event in events {
            if event["event_type"] != "mysql_exchange" {
                continue;
            }
            let Some(tokens) = tokens(event) else {
                continue;
            };
            let mut row = row_tokens(&tokens);
            if let Some((_, row)) = &mut row {
                row.retain(|column, _| columns.contains(column.as_str()));
            }
            result.facts.insert(
                event_key(event),
                Facts {
                    boundary: boundary_tokens(&tokens),
                    rollback: tokens.first().is_some_and(|token| token.is("rollback")),
                    write: tokens.first().is_some_and(|token| {
                        ["insert", "update", "delete"]
                            .iter()
                            .any(|word| token.is(word))
                    }),
                    row,
                },
            );
            if !successful(event) {
                continue;
            }
            for pattern in &patterns {
                if let Some(selection) = pattern.matches(event, &tokens) {
                    result
                        .selected
                        .insert((request_key(pattern.request), event_key(event)), selection);
                }
            }
        }
        result
    }

    pub fn selector(&self, request: &AsyncOwnershipRequest, event: &Value) -> Option<Selection> {
        self.selected
            .get(&(request_key(request), event_key(event)))
            .cloned()
    }
    pub fn row(&self, event: &Value) -> Option<&Row> {
        self.facts.get(&event_key(event))?.row.as_ref()
    }
    pub fn boundary(&self, event: &Value) -> Option<&'static str> {
        self.facts.get(&event_key(event))?.boundary
    }
    pub fn rollback(&self, event: &Value) -> bool {
        self.facts
            .get(&event_key(event))
            .is_some_and(|facts| facts.rollback)
    }
    pub fn write(&self, event: &Value) -> bool {
        self.facts
            .get(&event_key(event))
            .is_some_and(|facts| facts.write)
    }
}
