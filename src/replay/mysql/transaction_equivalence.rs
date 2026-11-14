//! Prove Source write spans from successful, connection-local Target delivery.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

mod member_comparison;
mod prefix;
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
    savepoint_predecessors: BTreeMap<usize, usize>,
    free_reads: BTreeSet<usize>,
    prefixes: prefix::Index,
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
pub(super) struct Witness {
    connection: Uuid,
    active: Option<Trace>,
    first_delivery: Option<ReadDelivery>,
}

impl Default for Witness {
    fn default() -> Self {
        Self {
            connection: Uuid::new_v4(),
            active: None,
            first_delivery: None,
        }
    }
}

impl Witness {
    pub(super) fn connection(&self) -> Uuid {
        self.connection
    }

    pub(super) fn has_active_transaction(&self) -> bool {
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
struct ReadDelivery {
    response: RecordedMysqlResponse,
    requested_at: DateTime<Utc>,
    delivered_at: DateTime<Utc>,
}

#[derive(Clone, Copy)]
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
    pub(super) fn can_defer_setup(
        &self,
        setup: usize,
        input_at: DateTime<Utc>,
        exchanges: &[ReplayExchange],
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
                        || exchanges[transaction.members[0]]
                            .record
                            .request_started_at
                            .is_some_and(|started| started > input_at)
                })
        })
    }

    pub(super) fn covered_by(&self, end: usize, connection: Uuid) -> bool {
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
    pub(super) fn requires_witness(&self, index: usize) -> bool {
        self.ends.get(&index).is_some_and(|&(r, t)| {
            let group = &self.requirements[r].transactions[t];
            (group.write_count != 0 || group.strict || group.savepoints) && group.witness.is_none()
        })
    }

    /// Only a registered, still-uncovered member can require an active Target
    /// transaction. Ordinary prefix reads and equivalent single writes can
    /// be admitted on an autocommitting socket.
    pub(super) fn requires_active_member(&self, index: usize) -> bool {
        !self.ends.contains_key(&index)
            && self.members.get(&index).is_some_and(|&(r, t)| {
                let group = &self.requirements[r].transactions[t];
                group.witness.is_none() && !group.can_cover_with_autocommit(index)
            })
    }

    /// A later Source member can only follow a savepoint control delivered
    /// in this very Target transaction. Matching SQL text cannot supply it.
    pub(super) fn permits_savepoint_member(&self, index: usize, witness: &Witness) -> bool {
        self.savepoint_predecessors
            .get(&index)
            .is_none_or(|previous| {
                witness
                    .active
                    .as_ref()
                    .is_some_and(|trace| trace.members.contains(previous))
            })
    }

    pub(super) fn missing_transaction_diagnostic(
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
    pub(super) fn preferred_end(&self, witness: &Witness, sql: &str) -> Option<usize> {
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

    pub(in crate::replay) fn prepare(
        &mut self,
        records: &[crate::replay::dependencies::DependencyRecord],
        optional: &BTreeMap<usize, OptionalSessionExchange>,
        scope: ReplaySource,
    ) -> Vec<source::Plan> {
        if scope.is_run_owned() {
            self.global_reads.record(super::source_records(records));
        }
        source::prepare(records, optional, scope, &self.global_reads)
    }

    pub(in crate::replay) fn install(
        &mut self,
        plans: Vec<source::Plan>,
        mapping: &BTreeMap<usize, usize>,
        exchanges: &[ReplayExchange],
    ) -> Vec<(usize, OptionalSessionExchange)> {
        self.prefixes.register(&plans, mapping, exchanges);
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
                dispatch_safe_before: plan.dispatch_safe_before,
            };
            for group in plan.transactions {
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
                if group.strict
                    && all
                        .iter()
                        .any(|&index| source::requires_source_setup(&exchanges[index].record))
                {
                    requirement
                        .source_reason
                        .get_or_insert("source_statement_effects_unsupported");
                    requirement.reason = requirement.source_reason.unwrap();
                    requirement.dispatch_safe_before = requirement
                        .dispatch_safe_before
                        .zip(exchanges[all[0]].record.request_started_at)
                        .map(|(before, started)| before.min(started));
                }
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
                    member_comparison: None,
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
                    let mut previous_savepoint = None;
                    for &index in &group.members {
                        self.members.insert(index, (id, transaction));
                        if let Some(previous) = previous_savepoint {
                            self.savepoint_predecessors.insert(index, previous);
                        }
                        if group.savepoints
                            && exchanges[index]
                                .record
                                .sql
                                .as_deref()
                                .and_then(crate::mysql::savepoint::parse)
                                .is_some()
                        {
                            previous_savepoint = Some(index);
                        }
                    }
                }
            }
            self.requirements.push(requirement);
            omissions.extend(self.covered_setups(id));
        }
        omissions
    }

    /// Only successful wire delivery and response-policy commit produce coverage.
    #[cfg(test)]
    pub(super) fn observe_delivery(
        &mut self,
        witness: &mut Witness,
        delivery: Delivery<'_>,
        end_admitted: impl Fn(usize) -> bool,
    ) -> Observation {
        self.observe_delivery_with_prefix(witness, delivery, None, end_admitted)
    }

    fn observe_delivery_with_prefix(
        &mut self,
        witness: &mut Witness,
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
                "member_comparison": group.member_comparison,
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
        read_delivery: Option<(&RecordedMysqlResponse, DateTime<Utc>, DateTime<Utc>)>,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
    ) {
        let command = delivery.command;
        let params = delivery.params;
        let sql = delivery.sql.to_owned();
        let prefix = self.prepare_mysql_prefix(witness, delivery, read_delivery, case);
        let exchanges = &self.mysql.exchanges;
        let observed = self
            .mysql
            .transaction_equivalence
            .observe_delivery_with_prefix(witness, delivery, prefix, |index| {
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
        let mysql = &mut self.mysql;
        if let Some(indices) = mysql.isolation.observe(
            witness.connection(),
            case,
            delivery,
            &mysql.transaction_equivalence,
            &mysql.exchanges,
        ) {
            for index in indices {
                if self.mysql.exchanges[index].status.is_available() {
                    self.mysql.exchanges[index].optional_session =
                        Some(OptionalSessionExchange::TransactionIsolation);
                    self.refresh_mysql_global_report(index);
                }
            }
        }
    }

    fn prepare_mysql_prefix(
        &self,
        witness: &mut Witness,
        delivery: Delivery<'_>,
        wire: Option<(&RecordedMysqlResponse, DateTime<Utc>, DateTime<Utc>)>,
        case: Option<&str>,
    ) -> Option<usize> {
        let previous = witness.first_delivery.take();
        let index = delivery.index?;
        let case = case?;
        let exchanges = &self.mysql.exchanges;
        let timeline = self.input_timing.as_ref()?;
        let window = |index: usize| {
            timeline.mysql_prefix_window(case, exchanges[index].record.request_started_at?)
        };
        let registry = &self.mysql.transaction_equivalence;
        if let Some(previous) = previous {
            let trace = witness.active.as_mut()?;
            let actual = *trace.members.first()?;
            let &(requirement, transaction) = registry.members.get(&index)?;
            let group = &registry.requirements[requirement].transactions[transaction];
            if let [expected, effect, _] = group.members.as_slice()
                && *effect == index
                && *expected != actual
                && registry.prefixes.covers(*expected, trace.neutral_first)
                && window(actual).is_some_and(|actual| window(*expected) == Some(actual))
                && self.mysql_prefix_response_matches(&exchanges[*expected].record, &previous, case)
            {
                trace.prefix_equivalent = true;
                tracing::debug!(
                    actual,
                    expected,
                    index,
                    "confirmed equivalent MySQL first read after locking statement"
                );
            }
            return None;
        }
        if !delivery.successful
            || delivery.after & 1 == 0
            || !witness
                .active
                .as_ref()
                .map_or(delivery.before & 1 == 0, |trace| {
                    trace.valid && trace.members.is_empty() && !trace.skipped_free_read
                })
        {
            return None;
        }
        let (response, requested_at, delivered_at) = wire?;
        let group = registry.prefixes.group_in_window(index, window)?;
        witness.first_delivery = Some(ReadDelivery {
            response: response.clone(),
            requested_at,
            delivered_at,
        });
        Some(group)
    }

    fn mysql_prefix_response_matches(
        &self,
        expected: &RecordedMysqlExchange,
        actual: &ReadDelivery,
        case: &str,
    ) -> bool {
        let Ok(source) = expected.response.materialize() else {
            return false;
        };
        let Some((owner, policy)) = self.replay_policy.as_ref().and_then(|policy| {
            let owner = &policy.request_contracts;
            owner.compiled_rules().map(|policy| (owner, policy))
        }) else {
            return source == actual.response;
        };
        let clocks = owner.contract_clocks(
            Some(case),
            contracts::source_started(expected),
            Some(actual.requested_at),
            expected.timestamp,
            Some(actual.delivered_at),
        );
        contracts::automatic::compare_response(
            policy,
            &source,
            &actual.response,
            expected.sql.as_deref(),
            expected.database.as_deref(),
            clocks,
        )
        .is_ok_and(|result| result.passed())
    }
}
