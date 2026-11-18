//! Install native transaction spans over the host's immutable exchange view.
use super::*;

impl Registry {
    pub fn prepare<'a, E: 'a>(
        &mut self,
        records: impl Iterator<Item = (usize, &'a RecordedMysqlExchange<E>)> + Clone,
        optional: &BTreeMap<usize, OptionalSessionExchange>,
        scope: ReplaySource,
    ) -> Vec<source::Plan> {
        if scope.is_run_owned() {
            self.global_reads.record(records.clone());
        }
        source::prepare(records, optional, scope, &self.global_reads)
    }

    pub fn install(
        &mut self,
        plans: Vec<source::Plan>,
        mapping: &BTreeMap<usize, usize>,
        context: &(impl SessionContext + ?Sized),
    ) -> Vec<(usize, OptionalSessionExchange)> {
        self.prefixes.register(&plans, mapping, context);
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
                    .filter(|i| context.exchange(*i).optional_session.is_none())
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
                        .any(|&index| source::requires_source_setup(context.exchange(index).record))
                {
                    requirement
                        .source_reason
                        .get_or_insert("source_statement_effects_unsupported");
                    requirement.reason = requirement.source_reason.unwrap();
                    requirement.dispatch_safe_before = requirement
                        .dispatch_safe_before
                        .zip(context.exchange(all[0]).record.request_started_at)
                        .map(|(before, started)| before.min(started));
                }
                let first_write = if group.strict || group.explicit && group.write_count != 0 {
                    0
                } else {
                    let first = group.first_write.unwrap_or(all.len() - 1);
                    all[..first]
                        .iter()
                        .position(|&i| {
                            context
                                .exchange(i)
                                .record
                                .sql
                                .as_deref()
                                .and_then(crate::savepoint::parse)
                                .is_some()
                        })
                        .unwrap_or(first)
                };
                let first = context.exchange(all[0]).record;
                let last = context.exchange(*all.last().unwrap()).record;
                let written = group.first_write.map(|i| context.exchange(all[i]).record);
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
                    context
                        .exchange(i)
                        .record
                        .sql
                        .as_deref()
                        .and_then(crate::savepoint::parse)
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
                        .filter(|i| context.exchange(*i).record.response.status == "error")
                        .collect(),
                    source_connection_id: first.connection_id.unwrap(),
                    first_sequence: first.query_sequence.unwrap(),
                    first_write_sequence: group
                        .first_write
                        .map(|i| context.exchange(all[i]).record.query_sequence.unwrap()),
                    last_sequence: last.query_sequence.unwrap(),
                    end: normalize_sql(last.sql.as_deref().unwrap_or_default()),
                    members: all[first_write..].to_vec(),
                    member_sequences: all[first_write..]
                        .iter()
                        .map(|i| context.exchange(*i).record.query_sequence.unwrap())
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
                            && context
                                .exchange(index)
                                .record
                                .sql
                                .as_deref()
                                .and_then(crate::savepoint::parse)
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
}

fn end_kind<E>(record: &RecordedMysqlExchange<E>) -> OptionalSessionExchange {
    if normalize_sql(record.sql.as_deref().unwrap_or_default()) == "rollback" {
        OptionalSessionExchange::Rollback
    } else {
        OptionalSessionExchange::Commit
    }
}
