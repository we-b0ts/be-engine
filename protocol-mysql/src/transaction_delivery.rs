//! Native transaction constraints derived from Source facts and confirmed delivery.
use crate::{
    model::MysqlValue as RecordedMysqlValue,
    recorded::{RecordedMysqlExchange, RecordedMysqlResponse},
    session_constraints::{SessionContext, SourceExchange},
    session_control::OptionalSessionExchange,
    transaction_source as source,
    values::normalize_sql,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use traffic_model::attribution::DependencyScope as ReplaySource;
use traffic_protocol::evidence::RecordSource;
use uuid::Uuid;

mod installation;
mod member_comparison;
mod prefix;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(test)]
mod tests;

#[derive(Debug, Default)]
pub struct Registry {
    requirements: Vec<Requirement>,
    setups: BTreeMap<usize, usize>,
    members: BTreeMap<usize, (usize, usize)>,
    ends: BTreeMap<usize, (usize, usize)>,
    savepoint_predecessors: BTreeMap<usize, usize>,
    free_reads: BTreeSet<usize>,
    prefixes: prefix::Index,
    global_reads: source::GlobalReads,
    rejected_ends: BTreeMap<usize, source::RejectedEnd>,
}

#[derive(Debug)]
struct Requirement {
    transactions: Vec<Transaction>,
    setups: Vec<usize>,
    reason: &'static str,
    blocked: bool,
    source_reason: Option<&'static str>,
    dispatch_safe_before: Option<DateTime<Utc>>,
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
    member_comparison: Option<member_comparison::MemberComparison>,
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
    fn can_cover_with_autocommit(&self, index: usize) -> bool {
        self.autocommit_eligible() && self.members.first() == Some(&index)
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
pub struct Witness<E = ()> {
    connection: Uuid,
    active: Option<Trace>,
    first_delivery: Option<ReadDelivery<E>>,
}

impl<E> Default for Witness<E> {
    fn default() -> Self {
        Self {
            connection: Uuid::new_v4(),
            active: None,
            first_delivery: None,
        }
    }
}

impl<E> Witness<E> {
    pub fn connection(&self) -> Uuid {
        self.connection
    }

    pub fn has_active_transaction(&self) -> bool {
        self.active.is_some()
    }
}

#[derive(Debug)]
struct Trace {
    id: Uuid,
    members: Vec<usize>,
    valid: bool,
    neutral_first: Option<usize>,
    prefix_equivalent: bool,
    skipped_free_read: bool,
}

#[derive(Debug)]
pub struct ReadDelivery<E> {
    pub response: RecordedMysqlResponse<E>,
    pub requested_at: DateTime<Utc>,
    pub delivered_at: DateTime<Utc>,
}

#[derive(Clone, Copy)]
pub struct Delivery<'a> {
    pub command: &'a str,
    pub params: Option<&'a [RecordedMysqlValue]>,
    pub sql: &'a str,
    pub index: Option<usize>,
    pub successful: bool,
    pub before: u16,
    pub after: u16,
}

#[derive(Default)]
pub struct Observation {
    pub omissions: Vec<(usize, OptionalSessionExchange)>,
    pub violation: Option<(usize, &'static str)>,
}

impl Registry {
    pub fn can_defer_setup(
        &self,
        setup: usize,
        input_at: DateTime<Utc>,
        started_at: impl Fn(usize) -> Option<DateTime<Utc>>,
    ) -> bool {
        self.setups.get(&setup).is_some_and(|&index| {
            let requirement = &self.requirements[index];
            !requirement.blocked
                && (requirement.source_reason.is_none()
                    || requirement
                        .dispatch_safe_before
                        .is_some_and(|end| input_at < end))
                && requirement.transactions.iter().all(|transaction| {
                    transaction.witness.is_some()
                        || started_at(transaction.members[0])
                            .is_some_and(|started| started > input_at)
                })
        })
    }

    pub fn covered_by(&self, end: usize, connection: Uuid) -> bool {
        self.ends.get(&end).is_some_and(|&(r, t)| {
            let requirement = &self.requirements[r];
            let group = &requirement.transactions[t];
            !requirement.blocked
                && group.witness.is_some_and(|coverage| {
                    coverage.connection == Some(connection) && coverage.transaction.is_some()
                        || coverage.connection.is_none() && group.write_count == 0 && !group.strict
                })
        })
    }
    pub fn requires_witness(&self, index: usize) -> bool {
        self.ends.get(&index).is_some_and(|&(r, t)| {
            let group = &self.requirements[r].transactions[t];
            (group.write_count != 0 || group.strict || group.savepoints) && group.witness.is_none()
        })
    }

    /// Only a registered, still-uncovered member can require an active Target
    /// transaction. Ordinary prefix reads and equivalent single writes can
    /// be admitted on an autocommitting socket.
    pub fn requires_active_member(&self, index: usize) -> bool {
        !self.ends.contains_key(&index)
            && self.members.get(&index).is_some_and(|&(r, t)| {
                let group = &self.requirements[r].transactions[t];
                group.witness.is_none() && !group.can_cover_with_autocommit(index)
            })
    }

    /// A later Source member can only follow a savepoint control delivered
    /// in this very Target transaction. Matching SQL text cannot supply it.
    pub fn permits_savepoint_member<E>(&self, index: usize, witness: &Witness<E>) -> bool {
        self.savepoint_predecessors
            .get(&index)
            .is_none_or(|previous| {
                witness
                    .active
                    .as_ref()
                    .is_some_and(|trace| trace.members.contains(previous))
            })
    }

    pub fn missing_transaction_diagnostic(
        &self,
        index: usize,
        connection: Uuid,
        status: u16,
    ) -> Option<Value> {
        let mut diagnostic = self.diagnostic(index)?;
        diagnostic["reason"] = "target_transaction_missing".into();
        diagnostic["stage"] = "candidate_admission".into();
        // The focused interval is first. Record only the live pre-send state.
        let group = &mut diagnostic["source_transactions"][0];
        group["target_connection_id"] = serde_json::json!(connection);
        group["target_transaction_id"] = Value::Null;
        group["target_status_before"] = status.into();
        group["target_status_after"] = Value::Null;
        group["missing_required_query_sequences"] = Value::Null;
        Some(diagnostic)
    }

    /// This socket's delivered write span selects its ordinary finite end.
    pub fn preferred_end<E>(&self, witness: &Witness<E>, sql: &str) -> Option<usize> {
        let trace = witness.active.as_ref().filter(|trace| trace.valid)?;
        let (requirement, transaction) = self.strict_location(trace)?;
        let requirement = &self.requirements[requirement];
        let group = &requirement.transactions[transaction];
        (!requirement.blocked
            && group.end == normalize_sql(sql)
            && group.witness.is_none()
            && self.same_members(trace, &group.members[..group.members.len() - 1]))
        .then(|| *group.members.last().unwrap())
    }

    fn strict_location(&self, trace: &Trace) -> Option<(usize, usize)> {
        trace
            .members
            .iter()
            .skip(usize::from(trace.neutral_first.is_some()))
            .find_map(|index| self.members.get(index).copied())
    }

    fn same_members(&self, trace: &Trace, expected: &[usize]) -> bool {
        trace.members == expected
            || expected.split_first().is_some_and(|(&first, rest)| {
                trace.prefix_equivalent
                    && self.prefixes.covers(first, trace.neutral_first)
                    && trace.members.get(1..) == Some(rest)
            })
    }

    /// Only successful wire delivery and response-policy commit produce coverage.
    #[cfg(test)]
    pub fn observe_delivery<E>(
        &mut self,
        witness: &mut Witness<E>,
        delivery: Delivery<'_>,
        end_admitted: impl Fn(usize) -> bool,
    ) -> Observation {
        self.observe_delivery_with_prefix(witness, delivery, None, end_admitted)
    }

    pub fn observe_delivery_with_prefix<E>(
        &mut self,
        witness: &mut Witness<E>,
        delivery: Delivery<'_>,
        confirmed_prefix: Option<usize>,
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
        let neutral_first = confirmed_prefix.filter(|_| {
            successful
                && after & 1 != 0
                && witness.active.as_ref().map_or(before & 1 == 0, |trace| {
                    trace.valid && trace.members.is_empty() && !trace.skipped_free_read
                })
        });
        let location = index
            .filter(|_| neutral_first.is_none())
            .and_then(|i| self.members.get(&i).copied());
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
                .and_then(|trace| self.strict_location(&trace))
                .map(|loc| self.reject(loc, "target_transaction_restarted"));
            witness.active = Some(Trace {
                id: Uuid::new_v4(),
                members: index
                    .filter(|i| self.members.contains_key(i))
                    .into_iter()
                    .collect(),
                valid,
                neutral_first: None,
                prefix_equivalent: false,
                skipped_free_read: false,
            });
            return violation.unwrap_or_default();
        }
        // A delivered native statement can start an implicit transaction after
        // SET AUTOCOMMIT=0. Only a matched business slot and the actual socket's
        // inactive -> IN_TRANS transition establish this connection-local trace.
        if witness.active.is_none()
            && successful
            && before & 0x200b == 0
            && after & 0x200b == 1
            && index.is_some_and(|index| {
                self.free_reads.contains(&index)
                    || self.members.contains_key(&index) && !self.ends.contains_key(&index)
            })
        {
            witness.active = Some(Trace {
                id: Uuid::new_v4(),
                members: Vec::new(),
                valid: true,
                neutral_first: None,
                prefix_equivalent: false,
                skipped_free_read: false,
            });
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
                && index.is_some_and(|index| group.can_cover_with_autocommit(index))
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
        if let Some(prefix) = neutral_first {
            if let Some(index) = index.filter(|i| self.members.contains_key(i)) {
                tracing::debug!(
                    index,
                    "matched a proven equivalent first MySQL transaction read"
                );
            }
            trace.neutral_first = Some(prefix);
            trace.members.extend(index);
            return Observation::default();
        }
        if trace.members.is_empty() && index.is_some_and(|i| self.free_reads.contains(&i)) {
            trace.skipped_free_read = true;
            return Observation::default();
        }
        if (trace.members.is_empty() || trace.members.len() == 1 && trace.neutral_first.is_some())
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
        let location = self.strict_location(&trace);
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
            || !self.same_members(&trace, &group.members)
            || sql != group.end
            || group.witness.is_some()
        {
            self.retain_member_comparison(loc, &trace, &sql);
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
    fn observe<E>(
        &mut self,
        witness: &mut Witness<E>,
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

    pub fn diagnostic(&self, index: usize) -> Option<Value> {
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
                "member_comparison": group.member_comparison,
            })).collect::<Vec<_>>(),
            "omitted_transactions": requirement.transactions.len().saturating_sub(8),
            "transaction_count": requirement.transactions.len(),
            "covered_transaction_count": requirement.transactions.iter().filter(|group| group.witness.is_some()).count(),
        }))
    }
}
