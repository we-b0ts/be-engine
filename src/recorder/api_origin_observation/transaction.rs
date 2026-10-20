//! Only an observed successful BEGIN can carry a selected anchor to boundaries.
use std::collections::BTreeMap;

use uuid::Uuid;

use super::{DependencyRequest, Origin, Rule, SelectionScope, request};
use crate::config::{BackgroundDependencyRuleConfig, MysqlBackgroundSelector};
use crate::mysql::sql::tokens;
use crate::recorder::MysqlExchangeEvent;

const MAX_CONNECTIONS: usize = 4096;
const STATUS_MASK: u16 = 0x200b;
const UNSUPPORTED_STATUS: u16 = 0x2008;

#[derive(Default)]
pub(super) struct Transactions {
    connections: BTreeMap<Uuid, Transaction>,
}

struct Transaction {
    last_sequence: u64,
    status: u16,
    possible: BTreeMap<usize, Option<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Boundary {
    Begin,
    End,
    Other,
}

impl Transactions {
    pub(super) fn select(
        &mut self,
        request: &DependencyRequest<'_>,
        rules: &[Rule],
        origins: &[Origin],
        selected: &mut BTreeMap<usize, SelectionScope>,
    ) {
        let DependencyRequest::Mysql { connection_id, .. } = request else {
            return;
        };
        let boundary = boundary(request);
        if boundary == Boundary::Begin {
            self.connections.remove(connection_id);
            return;
        }
        let Some(transaction) = self.connections.get_mut(connection_id) else {
            return;
        };
        transaction.possible.retain(|index, anchor| {
            let rule = &rules[*index];
            if !endpoint(&rule.config, request) {
                return false;
            }
            let direct = request::identity(&rule.config, request);
            let allowed = direct
                .as_deref()
                .and_then(|id| origins[rule.origin].capture.selection(id))
                .is_some()
                || member(&rule.config, request)
                || boundary == Boundary::End;
            if !allowed {
                return false;
            }
            if let Some(scope) = anchor
                .as_deref()
                .and_then(|id| origins[rule.origin].capture.selection(id))
            {
                selected.entry(*index).or_insert(scope);
            }
            true
        });
        if boundary == Boundary::End || transaction.possible.is_empty() {
            self.connections.remove(connection_id);
        }
    }

    pub(super) fn observe(
        &mut self,
        exchange: &MysqlExchangeEvent,
        rules: &[Rule],
        origins: &[Origin],
    ) {
        let request = request::mysql_request(exchange);
        let boundary = boundary(&request);
        let after = exchange.response.server_status;
        let basic_complete = exchange.outcome == crate::DependencyExchangeOutcome::Response
            && exchange.parse_warnings.is_empty();
        if boundary == Boundary::Begin {
            self.connections.remove(&exchange.connection_id);
            if !basic_complete
                || exchange.response.status != "ok"
                || after.is_none_or(|status| status & 0x2009 != 1)
                || self.connections.len() >= MAX_CONNECTIONS
            {
                return;
            }
            let possible = rules
                .iter()
                .enumerate()
                .filter(|(_, rule)| {
                    matches!(
                        rule.config,
                        BackgroundDependencyRuleConfig::Mysql {
                            include_transaction_boundaries: true,
                            ..
                        }
                    ) && endpoint(&rule.config, &request)
                })
                .map(|(index, _)| (index, None))
                .collect::<BTreeMap<_, _>>();
            if !possible.is_empty() {
                self.connections.insert(
                    exchange.connection_id,
                    Transaction {
                        last_sequence: exchange.query_sequence,
                        status: after.expect("complete BEGIN status"),
                        possible,
                    },
                );
            }
            return;
        }
        let Some(mut transaction) = self.connections.remove(&exchange.connection_id) else {
            return;
        };
        if boundary == Boundary::End
            || !basic_complete
            || !complete_body(exchange)
            || transaction.last_sequence.checked_add(1) != Some(exchange.query_sequence)
            || exchange.server_status_before.is_none_or(|before| {
                before & STATUS_MASK != transaction.status & STATUS_MASK || before & 0x2009 != 1
            })
            || after.is_none_or(|status| status & UNSUPPORTED_STATUS != 0 || status & 1 == 0)
        {
            return;
        }
        transaction.possible.retain(|index, anchor| {
            let rule = &rules[*index];
            if let Some(identity) = request::identity(&rule.config, &request)
                && origins[rule.origin].capture.selection(&identity).is_some()
            {
                if anchor.as_ref().is_some_and(|id| *id != identity) {
                    return false;
                }
                *anchor = Some(identity);
                true
            } else {
                member(&rule.config, &request)
            }
        });
        transaction.last_sequence = exchange.query_sequence;
        transaction.status = after.expect("complete transaction status");
        if !transaction.possible.is_empty() {
            self.connections.insert(exchange.connection_id, transaction);
        }
    }
}

fn boundary(request: &DependencyRequest<'_>) -> Boundary {
    let DependencyRequest::Mysql {
        command: "COM_QUERY",
        sql: Some(sql),
        ..
    } = request
    else {
        return Boundary::Other;
    };
    let Some(tokens) = tokens(sql) else {
        return Boundary::Other;
    };
    match tokens.as_slice() {
        [word] if word.is("begin") => Boundary::Begin,
        [start, transaction] if start.is("start") && transaction.is("transaction") => {
            Boundary::Begin
        }
        [word] if word.is("commit") || word.is("rollback") => Boundary::End,
        _ => Boundary::Other,
    }
}

fn endpoint(rule: &BackgroundDependencyRuleConfig, request: &DependencyRequest<'_>) -> bool {
    let (
        BackgroundDependencyRuleConfig::Mysql { selector, .. },
        DependencyRequest::Mysql {
            target_host,
            target_port,
            database,
            username,
            ..
        },
    ) = (rule, request)
    else {
        return false;
    };
    target_host.is_some_and(|host| host.eq_ignore_ascii_case(&selector.target_host))
        && *target_port == Some(selector.target_port)
        && *database == Some(selector.database.as_str())
        && *username == Some(selector.username.as_str())
}

fn member(rule: &BackgroundDependencyRuleConfig, request: &DependencyRequest<'_>) -> bool {
    let BackgroundDependencyRuleConfig::Mysql {
        transaction_members,
        ..
    } = rule
    else {
        return false;
    };
    transaction_members
        .iter()
        .any(|selector| member_query(selector, request))
}

fn member_query(selector: &MysqlBackgroundSelector, request: &DependencyRequest<'_>) -> bool {
    let DependencyRequest::Mysql {
        target_host,
        target_port,
        database,
        username,
        command,
        sql,
        ..
    } = request
    else {
        return false;
    };
    selector.matches_query(
        *target_host,
        *target_port,
        *database,
        *username,
        command,
        *sql,
    )
}

fn complete_body(exchange: &MysqlExchangeEvent) -> bool {
    let response = &exchange.response;
    match response.status.as_str() {
        "resultset" => {
            !response.rows_truncated
                && !response.columns.is_empty()
                && response.row_count == response.rows.len()
                && response
                    .rows
                    .iter()
                    .all(|row| row.len() == response.columns.len())
        }
        "ok" => response.affected_rows.is_some_and(|rows| rows <= 1),
        _ => false,
    }
}
