//! Prove Source write spans from successful, connection-local Target delivery.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

mod source;
mod source_evidence;
#[cfg(test)]
pub(super) mod tests;

#[derive(Debug, Default)]
pub(in crate::replay) struct Registry {
    requirements: Vec<Requirement>,
    setups: BTreeMap<usize, usize>,
    members: BTreeMap<usize, (usize, usize)>,
    ends: BTreeMap<usize, (usize, usize)>,
    free_reads: BTreeSet<usize>,
    global_reads: source_evidence::GlobalReads,
    rejected_ends: BTreeMap<usize, source::RejectedEnd>,
}

#[derive(Debug)]
struct Requirement {
    transactions: Vec<Transaction>,
    setups: Vec<usize>,
    reason: &'static str,
    blocked: bool,
    source_reason: Option<&'static str>,
}

#[derive(Debug)]
struct Transaction {
    members: Vec<usize>,
    member_sequences: Vec<u64>,
    observed: BTreeMap<Uuid, BTreeSet<usize>>,
    operation_count: usize,
    write_count: usize,
    explicit: bool,
    savepoints: bool,
    strict: bool,
    single_update_outcome: &'static str,
    source_error_code: Option<u16>,
    source_affected_rows: Option<u64>,
    expected_errors: BTreeSet<usize>,
    source_connection_id: Uuid,
    first_sequence: u64,
    first_write_sequence: Option<u64>,
    last_sequence: u64,
    end: String,
    witness: Option<Coverage>,
    target: Option<(Uuid, u16, u16)>,
}

#[derive(Debug, Clone, Copy)]
struct Coverage {
    connection: Option<Uuid>,
    transaction: Option<Uuid>,
}

impl Transaction {
    fn autocommit_eligible(&self) -> bool {
        self.write_count == 1
            && !self.strict
            && !self.savepoints
            && !self.explicit
            && (self.end == "commit" && self.expected_errors.is_empty()
                || self.end == "rollback"
                    && matches!(self.single_update_outcome, "error" | "zero_affected_rows"))
    }
    fn missing_sequences(&self) -> Option<Vec<u64>> {
        if self.witness.is_some() {
            return Some(Vec::new());
        }
        let connection = self.target?.0;
        let observed = self.observed.get(&connection)?;
        Some(
            self.members
                .iter()
                .zip(&self.member_sequences)
                .filter(|(index, _)| !observed.contains(index))
                .take(8)
                .map(|(_, sequence)| *sequence)
                .collect(),
        )
    }
}

#[derive(Debug)]
pub(super) struct Witness {
    connection: Uuid,
    active: Option<Trace>,
}

impl Default for Witness {
    fn default() -> Self {
        Self {
            connection: Uuid::new_v4(),
            active: None,
        }
    }
}

#[derive(Debug)]
struct Trace {
    id: Uuid,
    members: Vec<usize>,
    valid: bool,
}

pub(super) struct Delivery<'a> {
    pub(super) command: &'a str,
    pub(super) params: Option<&'a [RecordedMysqlValue]>,
    pub(super) sql: &'a str,
    pub(super) index: Option<usize>,
    pub(super) successful: bool,
    pub(super) before: u16,
    pub(super) after: u16,
}

#[derive(Default)]
pub(super) struct Observation {
    omissions: Vec<(usize, OptionalSessionExchange)>,
    violation: Option<(usize, &'static str)>,
}

impl Registry {
    pub(super) fn requires_witness(&self, index: usize) -> bool {
        self.ends.get(&index).is_some_and(|&(r, t)| {
            let group = &self.requirements[r].transactions[t];
            (group.write_count != 0 || group.strict || group.savepoints) && group.witness.is_none()
        })
    }

    /// This socket's delivered write span selects its ordinary finite end.
    pub(super) fn preferred_end(&self, witness: &Witness, sql: &str) -> Option<usize> {
        let trace = witness.active.as_ref().filter(|trace| trace.valid)?;
        let (requirement, transaction) = self.members.get(trace.members.first()?)?;
        let requirement = &self.requirements[*requirement];
        let group = &requirement.transactions[*transaction];
        (!requirement.blocked
            && group.end == normalize_sql(sql)
            && group.witness.is_none()
            && trace.members == group.members[..group.members.len() - 1])
            .then(|| *group.members.last().unwrap())
    }

    pub(in crate::replay) fn prepare(
        &mut self,
        records: &[crate::replay::dependencies::DependencyRecord],
        optional: &BTreeMap<usize, OptionalSessionExchange>,
        scope: ReplaySource,
    ) -> Vec<source::Plan> {
        if scope == ReplaySource::Global {
            self.global_reads.record(records);
        }
        source::prepare(records, optional, scope, &self.global_reads)
    }

    pub(in crate::replay) fn install(
        &mut self,
        plans: Vec<source::Plan>,
        mapping: &BTreeMap<usize, usize>,
        exchanges: &[ReplayExchange],
    ) -> Vec<(usize, OptionalSessionExchange)> {
        let mut omissions = Vec::new();
        for plan in plans {
            for rejected in plan.failed_ends {
                if let Some(&index) = mapping.get(&rejected.index) {
                    self.rejected_ends.insert(index, rejected);
                }
            }
            let id = self.requirements.len();
            let mut pending_free = Vec::new();
            let mut pending_ends = Vec::new();
            let mut pending_omissions = Vec::new();
            let mut requirement = Requirement {
                transactions: Vec::new(),
                setups: plan
                    .setups
                    .iter()
                    .filter_map(|i| mapping.get(i).copied())
                    .filter(|i| exchanges[*i].optional_session.is_none())
                    .collect(),
                reason: plan
                    .reason
                    .unwrap_or("target_transaction_coverage_required"),
                blocked: false,
                source_reason: plan.reason,
            };
            for group in plan.transactions {
                if group.strict {
                    requirement
                        .source_reason
                        .get_or_insert("source_statement_effects_unsupported");
                    requirement.reason = requirement.source_reason.unwrap();
                }
                let Some(all) = group
                    .members
                    .iter()
                    .map(|i| mapping.get(i).copied())
                    .collect::<Option<Vec<_>>>()
                else {
                    requirement.reason = "source_scope_incomplete";
                    requirement.blocked = true;
                    break;
                };
                let first_write = if group.strict || group.explicit && group.write_count != 0 {
                    0
                } else {
                    let first = group.first_write.unwrap_or(all.len() - 1);
                    all[..first]
                        .iter()
                        .position(|&i| {
                            exchanges[i]
                                .record
                                .sql
                                .as_deref()
                                .and_then(crate::mysql::savepoint::parse)
                                .is_some()
                        })
                        .unwrap_or(first)
                };
                let first = &exchanges[all[0]].record;
                let last = &exchanges[*all.last().unwrap()].record;
                let written = group.first_write.map(|i| &exchanges[all[i]].record);
                let single_update_outcome = if group.write_count == 1 {
                    written
                        .and_then(source::update_outcome)
                        .unwrap_or("unsupported")
                } else {
                    "unsupported"
                };
                let transaction = requirement.transactions.len();
                pending_ends.push((*all.last().unwrap(), (id, transaction)));
                pending_free.extend(all[..first_write].iter().copied());
                let has_savepoints = all.iter().any(|&i| {
                    exchanges[i]
                        .record
                        .sql
                        .as_deref()
                        .and_then(crate::mysql::savepoint::parse)
                        .is_some()
                });
                let witness = (group.write_count == 0 && !group.strict && !has_savepoints)
                    .then_some(Coverage {
                        connection: None,
                        transaction: None,
                    });
                if witness.is_some() {
                    pending_omissions.push((*all.last().unwrap(), end_kind(last)));
                }
                requirement.transactions.push(Transaction {
                    operation_count: all.len() - 1,
                    write_count: group.write_count,
                    explicit: group.explicit,
                    savepoints: has_savepoints,
                    strict: group.strict,
                    single_update_outcome,
                    source_error_code: written.and_then(|r| r.response.error_code),
                    source_affected_rows: written.and_then(|r| r.response.affected_rows),
                    expected_errors: all
                        .iter()
                        .copied()
                        .filter(|i| exchanges[*i].record.response.status == "error")
                        .collect(),
                    source_connection_id: first.connection_id.unwrap(),
                    first_sequence: first.query_sequence.unwrap(),
                    first_write_sequence: group
                        .first_write
                        .map(|i| exchanges[all[i]].record.query_sequence.unwrap()),
                    last_sequence: last.query_sequence.unwrap(),
                    end: normalize_sql(last.sql.as_deref().unwrap_or_default()),
                    members: all[first_write..].to_vec(),
                    member_sequences: all[first_write..]
                        .iter()
                        .map(|i| exchanges[*i].record.query_sequence.unwrap())
                        .collect(),
                    observed: BTreeMap::new(),
                    witness,
                    target: None,
                });
            }
            if requirement.blocked {
                requirement.transactions.clear();
            } else {
                self.ends.extend(pending_ends);
                self.free_reads.extend(pending_free);
                omissions.extend(pending_omissions);
            }
            for &index in &requirement.setups {
                self.setups.insert(index, id);
            }
            for (transaction, group) in requirement.transactions.iter().enumerate() {
                if group.write_count != 0 || group.strict || group.savepoints {
                    for &index in &group.members {
                        self.members.insert(index, (id, transaction));
                    }
                }
            }
            self.requirements.push(requirement);
            omissions.extend(self.covered_setups(id));
        }
        omissions
    }

    /// Only successful wire delivery and response-policy commit produce coverage.
    pub(super) fn observe_delivery(
        &mut self,
        witness: &mut Witness,
        delivery: Delivery<'_>,
        end_admitted: impl Fn(usize) -> bool,
    ) -> Observation {
        if self.members.is_empty() {
            return Observation::default();
        }
        let Delivery {
            sql,
            index,
            successful,
            before,
            after,
            ..
        } = delivery;
        let sql = normalize_sql(sql);
        let location = index.and_then(|i| self.members.get(&i).copied());
        if let Some((r, t)) = location {
            let group = &mut self.requirements[r].transactions[t];
            if group.witness.is_none() {
                group.target = Some((witness.connection, before, after));
                if let Some(index) = index {
                    group
                        .observed
                        .entry(witness.connection)
                        .or_default()
                        .insert(index);
                }
            }
        }
        let expected_error = location.is_some_and(|(r, t)| {
            index.is_some_and(|i| {
                self.requirements[r].transactions[t]
                    .expected_errors
                    .contains(&i)
            })
        });
        if successful == expected_error {
            if let Some(trace) = &mut witness.active {
                trace.valid = false;
            }
            return location.map_or_else(Observation::default, |loc| {
                self.reject(loc, "target_transaction_failed")
            });
        }
        if matches!(sql.as_str(), "begin" | "start transaction") {
            let previous = witness.active.take();
            let valid = previous.is_none() && before & 1 == 0 && after & 1 != 0;
            let violation = previous
                .and_then(|trace| {
                    trace
                        .members
                        .iter()
                        .find_map(|i| self.members.get(i).copied())
                })
                .map(|loc| self.reject(loc, "target_transaction_restarted"));
            witness.active = Some(Trace {
                id: Uuid::new_v4(),
                members: index
                    .filter(|i| self.members.contains_key(i))
                    .into_iter()
                    .collect(),
                valid,
            });
            return violation.unwrap_or_default();
        }
        if let Some(loc @ (r, t)) = location {
            let group = &self.requirements[r].transactions[t];
            if group.witness.is_some()
                && witness
                    .active
                    .as_ref()
                    .is_none_or(|trace| trace.members.is_empty())
            {
                if matches!(sql.as_str(), "commit" | "rollback") {
                    witness.active = None;
                }
                return Observation::default();
            }
            if witness.active.is_none()
                && group.autocommit_eligible()
                && group.members.first().copied() == index
                && before & 3 == 2
                && after & 3 == 2
            {
                if !self.previous_admitted(loc, &end_admitted) {
                    return self.reject(loc, "target_transaction_order_differ");
                }
                return self.cover(
                    loc,
                    Coverage {
                        connection: Some(witness.connection),
                        transaction: None,
                    },
                );
            }
        }
        let Some(trace) = &mut witness.active else {
            return location.map_or_else(Observation::default, |loc| {
                self.reject(loc, "target_transaction_missing")
            });
        };
        if trace.members.is_empty() && index.is_some_and(|i| self.free_reads.contains(&i)) {
            return Observation::default();
        }
        if trace.members.is_empty()
            && let Some(loc) = location
            && !self.previous_admitted(loc, &end_admitted)
        {
            trace.valid = false;
            return self.reject(loc, "target_transaction_order_differ");
        }
        if let Some(index) = index {
            trace.members.push(index);
        } else if !matches!(sql.as_str(), "commit" | "rollback") {
            trace.valid = false;
        }
        if !matches!(sql.as_str(), "commit" | "rollback") {
            return Observation::default();
        }
        let trace = witness.active.take().unwrap();
        let location = trace
            .members
            .iter()
            .find_map(|i| self.members.get(i).copied());
        let Some(loc @ (r, t)) = location else {
            return Observation::default();
        };
        let group = &mut self.requirements[r].transactions[t];
        if group.witness.is_none() {
            group.target = Some((witness.connection, before, after));
        }
        let requirement = &self.requirements[r];
        let group = &requirement.transactions[t];
        if requirement.blocked
            || !trace.valid
            || before & 1 == 0
            || after & 1 != 0
            || trace.members != group.members
            || sql != group.end
            || group.witness.is_some()
        {
            return self.reject(loc, "target_transaction_members_or_end_differ");
        }
        self.cover(
            loc,
            Coverage {
                connection: Some(witness.connection),
                transaction: Some(trace.id),
            },
        )
    }

    fn previous_admitted(&self, (r, t): (usize, usize), admitted: &impl Fn(usize) -> bool) -> bool {
        self.requirements[r].transactions[..t]
            .iter()
            .all(|group| group.witness.is_some() || admitted(*group.members.last().unwrap()))
    }

    fn cover(&mut self, (r, t): (usize, usize), coverage: Coverage) -> Observation {
        let requirement = &mut self.requirements[r];
        if requirement.blocked {
            return Observation::default();
        }
        let group = &mut requirement.transactions[t];
        group.witness = Some(coverage);
        let end = *group.members.last().unwrap();
        let kind = if group.end == "rollback" {
            OptionalSessionExchange::Rollback
        } else {
            OptionalSessionExchange::Commit
        };
        let mut omissions = vec![(end, kind)];
        omissions.extend(self.covered_setups(r));
        Observation {
            omissions,
            violation: None,
        }
    }

    fn covered_setups(&mut self, r: usize) -> Vec<(usize, OptionalSessionExchange)> {
        let requirement = &mut self.requirements[r];
        if requirement.blocked
            || requirement.source_reason.is_some()
            || requirement
                .transactions
                .iter()
                .any(|group| group.witness.is_none())
        {
            return Vec::new();
        }
        requirement.reason = if requirement.transactions.iter().any(|group| {
            group.write_count == 1 && group.witness.is_some_and(|w| w.transaction.is_none())
        }) {
            "target_autocommit_single_write"
        } else {
            "equivalent_write_transactions"
        };
        requirement
            .setups
            .iter()
            .map(|&i| (i, OptionalSessionExchange::TransactionAutocommit))
            .collect()
    }

    fn reject(&mut self, (r, t): (usize, usize), reason: &'static str) -> Observation {
        let requirement = &mut self.requirements[r];
        if requirement.blocked {
            return Observation::default();
        }
        requirement.blocked = true;
        requirement.reason = reason;
        Observation {
            omissions: Vec::new(),
            violation: Some((*requirement.transactions[t].members.last().unwrap(), reason)),
        }
    }

    #[cfg(test)]
    fn observe(
        &mut self,
        witness: &mut Witness,
        sql: &str,
        index: Option<usize>,
        successful: bool,
    ) -> Vec<usize> {
        let before = if witness.active.is_some() { 3 } else { 0 };
        let after = match normalize_sql(sql).as_str() {
            "begin" | "start transaction" => 3,
            "commit" | "rollback" => 2,
            _ => before,
        };
        self.observe_delivery(
            witness,
            Delivery {
                command: "COM_QUERY",
                params: None,
                sql,
                index,
                successful,
                before,
                after,
            },
            |_| false,
        )
        .omissions
        .into_iter()
        .filter_map(|(i, kind)| {
            (kind == OptionalSessionExchange::TransactionAutocommit).then_some(i)
        })
        .collect()
    }

    pub(in crate::replay) fn diagnostic(&self, index: usize) -> Option<Value> {
        if let Some(rejected) = self.rejected_ends.get(&index) {
            return Some(serde_json::json!({
                "kind": "mysql_autocommit_transaction_coverage",
                "reason": rejected.reason,
                "source_proof_status": "incomplete",
                "source_proof_rejection": {
                    "failure_query_sequence": rejected.failure_query_sequence,
                    "missing_query_sequences": rejected.missing_query_sequences,
                    "omitted_missing_query_sequences": rejected.omitted_missing_query_sequences,
                },
                "source_transactions": [{
                    "source_connection_id": rejected.source_connection_id,
                    "last_query_sequence": rejected.source_query_sequence,
                    "end": rejected.end,
                }],
            }));
        }
        let r = self.setups.get(&index).copied().or_else(|| {
            self.members
                .get(&index)
                .or_else(|| self.ends.get(&index))
                .map(|(r, _)| *r)
        })?;
        let requirement = &self.requirements[r];
        // A bounded report must include the interval selected by this member,
        // even when a persistent Source session contains more than eight ends.
        let focused = self
            .members
            .get(&index)
            .or_else(|| self.ends.get(&index))
            .map(|(_, transaction)| *transaction);
        let transactions = focused
            .into_iter()
            .chain((0..requirement.transactions.len()).filter(|i| Some(*i) != focused))
            .take(8)
            .map(|i| &requirement.transactions[i]);
        Some(serde_json::json!({
            "kind": "mysql_autocommit_transaction_coverage", "reason": requirement.reason,
            "source_transactions": transactions.map(|group| serde_json::json!({
                "source_connection_id": group.source_connection_id,
                "first_query_sequence": group.first_sequence,
                "first_write_query_sequence": group.first_write_sequence,
                "last_query_sequence": group.last_sequence,
                "operation_count": group.operation_count,
                "required_operation_count": group.members.len() - 1,
                "write_count": group.write_count, "end": group.end,
                "strict_source_effects": group.strict,
                "single_update_outcome": group.single_update_outcome,
                "source_error_code": group.source_error_code,
                "source_affected_rows": group.source_affected_rows,
                "autocommit_eligible": group.autocommit_eligible(),
                "missing_required_query_sequences": group.missing_sequences(),
                "target_connection_id": group.witness.and_then(|w| w.connection).or_else(|| group.target.map(|(c, _, _)| c)),
                "target_transaction_id": group.witness.and_then(|w| w.transaction),
                "target_status_before": group.target.map(|(_, before, _)| before),
                "target_status_after": group.target.map(|(_, _, after)| after),
            })).collect::<Vec<_>>(),
            "omitted_transactions": requirement.transactions.len().saturating_sub(8),
            "transaction_count": requirement.transactions.len(),
            "covered_transaction_count": requirement.transactions.iter().filter(|group| group.witness.is_some()).count(),
        }))
    }
}

fn end_kind(record: &RecordedMysqlExchange) -> OptionalSessionExchange {
    if normalize_sql(record.sql.as_deref().unwrap_or_default()) == "rollback" {
        OptionalSessionExchange::Rollback
    } else {
        OptionalSessionExchange::Commit
    }
}

impl ReplayState {
    pub(super) fn observe_mysql_transaction(
        &mut self,
        witness: &mut Witness,
        delivery: Delivery<'_>,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
    ) {
        let command = delivery.command;
        let params = delivery.params;
        let sql = delivery.sql.to_owned();
        let exchanges = &self.mysql.exchanges;
        let observed =
            self.mysql
                .transaction_equivalence
                .observe_delivery(witness, delivery, |index| {
                    matches!(
                        exchanges[index].status,
                        ReplayExchangeStatus::Responding | ReplayExchangeStatus::Consumed
                    )
                });
        for (index, kind) in observed.omissions {
            if self.mysql.exchanges[index].status.is_available() {
                self.mysql.exchanges[index].optional_session = Some(kind);
                self.refresh_mysql_global_report(index);
            }
        }
        if let Some((index, reason)) = observed.violation {
            let source = self.mysql.exchanges[index].source;
            let diagnostic = self.mysql.transaction_equivalence.diagnostic(index);
            self.record_unmatched_in_case(
                case,
                identity,
                command,
                Some(&sql),
                params,
                &format!("MySQL transaction coverage: {reason}"),
            );
            if let Some(event) = self.mysql.events.unmatched_queries.last_mut() {
                event.recorded_source = Some(source);
                event.recorded_index = Some(index);
                event.diagnostic = diagnostic;
            }
        }
    }
}
