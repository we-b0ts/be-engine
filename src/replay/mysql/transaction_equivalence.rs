//! Match implicit Source transactions to complete explicit Target transactions.
//! Source classification grants no omission until actual successful delivery proves coverage.
use super::*;
use std::collections::BTreeMap;

mod source;
#[cfg(test)]
pub(super) mod tests;

#[derive(Debug, Default)]
pub(in crate::replay) struct Registry {
    requirements: Vec<Requirement>,
    setups: BTreeMap<usize, usize>,
    members: BTreeMap<usize, (usize, usize)>,
}

#[derive(Debug)]
struct Requirement {
    transactions: Vec<Transaction>,
    reason: &'static str,
    blocked: bool,
}

#[derive(Debug)]
struct Transaction {
    members: Vec<usize>,
    first_sequence: u64,
    last_sequence: u64,
    end: String,
    witness: Option<(Uuid, Uuid)>,
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

impl Registry {
    pub(in crate::replay) fn prepare(
        records: &[crate::replay::dependencies::DependencyRecord],
        optional: &BTreeMap<usize, OptionalSessionExchange>,
    ) -> Vec<source::Plan> {
        source::prepare(records, optional)
    }

    pub(in crate::replay) fn install(
        &mut self,
        plans: Vec<source::Plan>,
        mapping: &BTreeMap<usize, usize>,
        exchanges: &[ReplayExchange],
    ) {
        for plan in plans {
            let id = self.requirements.len();
            let mut requirement = Requirement {
                transactions: Vec::new(),
                reason: "target_transaction_coverage_required",
                blocked: false,
            };
            match plan.transactions {
                Err(reason) => {
                    requirement.reason = reason;
                    requirement.blocked = true;
                }
                Ok(groups) => {
                    for group in groups {
                        let Some(members) = group
                            .iter()
                            .map(|i| mapping.get(i).copied())
                            .collect::<Option<Vec<_>>>()
                        else {
                            requirement.reason = "source_scope_incomplete";
                            requirement.blocked = true;
                            break;
                        };
                        let first = &exchanges[members[0]].record;
                        let last = &exchanges[*members.last().unwrap()].record;
                        requirement.transactions.push(Transaction {
                            first_sequence: first.query_sequence.unwrap(),
                            last_sequence: last.query_sequence.unwrap(),
                            end: normalize_sql(last.sql.as_deref().unwrap_or_default()),
                            members,
                            witness: None,
                        });
                    }
                }
            }
            let setups: Vec<_> = plan
                .setups
                .iter()
                .filter_map(|i| mapping.get(i).copied())
                .filter(|i| exchanges[*i].optional_session.is_none())
                .collect();
            if setups.is_empty() {
                continue;
            }
            for index in setups {
                self.setups.insert(index, id);
            }
            for (transaction, group) in requirement.transactions.iter().enumerate() {
                for index in &group.members {
                    self.members.insert(*index, (id, transaction));
                }
            }
            self.requirements.push(requirement);
        }
    }

    /// Called after successful wire delivery and ordinary response-policy commit.
    /// Connection-local traces cannot borrow another socket's BEGIN or COMMIT.
    pub(super) fn observe_delivery(
        &mut self,
        witness: &mut Witness,
        sql: &str,
        index: Option<usize>,
        successful: bool,
        end_admitted: impl Fn(usize) -> bool,
    ) -> Vec<usize> {
        if self.setups.is_empty() {
            return Vec::new();
        }
        let sql = normalize_sql(sql);
        if !successful {
            self.reject(
                witness
                    .active
                    .as_ref()
                    .map(|t| t.members.as_slice())
                    .unwrap_or_default(),
                "target_transaction_failed",
            );
            if let Some(trace) = &mut witness.active {
                trace.valid = false;
            }
            return Vec::new();
        }
        if matches!(sql.as_str(), "begin" | "start transaction") {
            let valid = witness.active.is_none();
            if let Some(trace) = witness.active.take() {
                self.reject(&trace.members, "target_transaction_restarted");
            }
            witness.active = Some(Trace {
                id: Uuid::new_v4(),
                members: Vec::new(),
                valid,
            });
            return Vec::new();
        }
        let Some(trace) = &mut witness.active else {
            if let Some(index) = index {
                self.reject(&[index], "target_transaction_missing");
            }
            return Vec::new();
        };
        if let Some(index) = index {
            if trace.members.is_empty()
                && let Some((requirement, transaction)) = self.members.get(&index).copied()
                && self.requirements[requirement].transactions[..transaction]
                    .iter()
                    .any(|group| {
                        group.witness.is_none() && !end_admitted(*group.members.last().unwrap())
                    })
            {
                self.reject(&[index], "target_transaction_order_differ");
                trace.valid = false;
            }
            trace.members.push(index);
        } else if !matches!(sql.as_str(), "commit" | "rollback") {
            trace.valid = false;
        }
        if !matches!(sql.as_str(), "commit" | "rollback") {
            return Vec::new();
        }
        let trace = witness.active.take().unwrap();
        let location = trace
            .members
            .first()
            .and_then(|i| self.members.get(i))
            .copied();
        let Some((requirement, transaction)) = location else {
            self.reject(&trace.members, "target_transaction_members_differ");
            return Vec::new();
        };
        let source = &mut self.requirements[requirement];
        let group = &mut source.transactions[transaction];
        if source.blocked
            || !trace.valid
            || trace.members != group.members
            || sql != group.end
            || group.witness.is_some()
        {
            self.reject(&trace.members, "target_transaction_members_or_end_differ");
            return Vec::new();
        }
        group.witness = Some((witness.connection, trace.id));
        if source
            .transactions
            .iter()
            .all(|group| group.witness.is_some())
        {
            source.reason = "equivalent_explicit_transactions";
            self.setups
                .iter()
                .filter_map(|(index, id)| (*id == requirement).then_some(*index))
                .collect()
        } else {
            Vec::new()
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
        self.observe_delivery(witness, sql, index, successful, |_| false)
    }

    fn reject(&mut self, members: &[usize], reason: &'static str) {
        for index in members {
            if let Some((id, _)) = self.members.get(index) {
                let requirement = &mut self.requirements[*id];
                if !requirement.blocked {
                    requirement.blocked = true;
                    requirement.reason = reason;
                }
            }
        }
    }

    pub(in crate::replay) fn diagnostic(&self, index: usize) -> Option<Value> {
        let requirement = &self.requirements[*self.setups.get(&index)?];
        Some(serde_json::json!({
            "kind": "mysql_autocommit_transaction_coverage",
            "reason": requirement.reason,
            "source_transactions": requirement.transactions.iter().take(8).map(|group| serde_json::json!({
                "first_query_sequence": group.first_sequence,
                "last_query_sequence": group.last_sequence,
                "operation_count": group.members.len() - 1,
                "end": group.end,
                "target_connection_id": group.witness.map(|w| w.0),
                "target_transaction_id": group.witness.map(|w| w.1),
            })).collect::<Vec<_>>(),
            "omitted_transactions": requirement.transactions.len().saturating_sub(8),
            "transaction_count": requirement.transactions.len(),
            "covered_transaction_count": requirement.transactions.iter().filter(|group| group.witness.is_some()).count(),
        }))
    }
}

impl ReplayState {
    pub(super) fn observe_mysql_transaction(
        &mut self,
        witness: &mut Witness,
        sql: &str,
        index: Option<usize>,
        successful: bool,
    ) {
        let exchanges = &self.mysql.exchanges;
        let covered = self.mysql.transaction_equivalence.observe_delivery(
            witness,
            sql,
            index,
            successful,
            // A client may use another pool socket as soon as it sees COMMIT's
            // response, before this socket completes delivery bookkeeping.
            // Admission orders transactions; only successful delivery grants coverage.
            |index| {
                matches!(
                    exchanges[index].status,
                    ReplayExchangeStatus::Responding | ReplayExchangeStatus::Consumed
                )
            },
        );
        for index in covered {
            if self.mysql.exchanges[index].status.is_available() {
                self.mysql.exchanges[index].optional_session =
                    Some(OptionalSessionExchange::TransactionAutocommit);
                self.refresh_mysql_global_report(index);
            }
        }
    }
}
