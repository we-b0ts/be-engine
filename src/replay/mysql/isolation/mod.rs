//! Source-proven SESSION override/restoration versus one explicit NEXT transaction.
//! Values, real deliveries and business transaction coverage keep their owners.
use super::*;
use crate::mysql::isolation::{Level, Scope};

mod source;
#[cfg(test)]
pub(in crate::replay::mysql) mod tests;

pub(in crate::replay::mysql) fn source_session_control(record: &RecordedMysqlExchange) -> bool {
    source::session_control(record)
}

#[derive(Debug)]
struct Profile {
    plan: source::Plan,
    target: Option<Uuid>,
    phase: &'static str,
    observed: usize,
    end_omission_proven: bool,
}

#[derive(Debug)]
struct Binding {
    setup: usize,
    begun: bool,
    valid: bool,
    seen: BTreeSet<usize>,
}

#[derive(Debug, Default)]
pub(in crate::replay) struct Registry {
    baselines: HashMap<Uuid, Option<source::Baseline>>,
    ambiguous_defaults: Vec<MysqlDependencyIdentity>,
    defaults: HashMap<Uuid, Option<Level>>,
    exhausted: bool,
    profiles: BTreeMap<usize, Profile>,
    owners: HashMap<usize, usize>,
    bindings: HashMap<Uuid, Binding>,
}

impl Registry {
    pub(in crate::replay) fn install(
        &mut self,
        plans: Vec<source::Plan>,
        indices: &BTreeMap<usize, usize>,
    ) {
        for mut plan in plans {
            if self.profiles.len() >= 4096 {
                break;
            }
            let map = |index: usize| indices.get(&index).copied();
            let (Some(setup), Some(end), Some(reset)) =
                (map(plan.setup), map(plan.end), map(plan.reset))
            else {
                continue;
            };
            let Some(required) = plan
                .required
                .iter()
                .map(|i| map(*i))
                .collect::<Option<BTreeSet<_>>>()
            else {
                continue;
            };
            plan.setup = setup;
            plan.end = end;
            plan.reset = reset;
            plan.required = required;
            for index in plan.required.iter().copied().chain([setup, reset]) {
                self.owners.insert(index, setup);
            }
            self.profiles.insert(
                setup,
                Profile {
                    plan,
                    target: None,
                    phase: "unobserved",
                    observed: 0,
                    end_omission_proven: false,
                },
            );
        }
    }

    pub(in crate::replay::mysql) fn can_match(
        &self,
        index: usize,
        connection: Uuid,
        status: u16,
        sql: &str,
        exchanges: &[ReplayExchange],
    ) -> bool {
        let Some(profile) = self.profiles.get(&index) else {
            return false;
        };
        let p = &profile.plan;
        if self.exhausted
            || status & 0x200b != 2
            || self.bindings.contains_key(&connection)
            || self.ambiguous_defaults.contains(&p.identity)
            || self
                .defaults
                .get(&connection)
                .is_some_and(|known| *known != Some(p.baseline))
            || self.defaults.len() >= 4096 && !self.defaults.contains_key(&connection)
            || self
                .baselines
                .values()
                .flatten()
                .any(|known| known.identity == p.identity && known.level != p.baseline)
            || crate::mysql::isolation::setting(sql) != Some((Scope::Next, p.level))
        {
            return false;
        }
        self.profiles
            .values()
            .filter(|prior| {
                prior.plan.case == p.case
                    && prior.plan.source_connection == p.source_connection
                    && prior.plan.sequence < p.sequence
            })
            .all(|prior| {
                let reset = &exchanges[prior.plan.reset];
                reset.status.is_consumed()
                    || reset.optional_session == Some(OptionalSessionExchange::TransactionIsolation)
            })
    }

    pub(in crate::replay::mysql) fn permits(&self, connection: Uuid, index: usize) -> bool {
        if let Some(profile) = self
            .owners
            .get(&index)
            .and_then(|owner| self.profiles.get(owner))
            && profile.phase != "covered"
            && profile.target.is_some_and(|target| target != connection)
        {
            return false;
        }
        self.bindings.get(&connection).is_none_or(|binding| {
            binding.begun && self.profiles[&binding.setup].plan.required.contains(&index)
        })
    }

    pub(in crate::replay::mysql) fn observe(
        &mut self,
        connection: Uuid,
        case: Option<&str>,
        delivery: transaction_equivalence::Delivery<'_>,
        transactions: &transaction_equivalence::Registry,
    ) -> Option<usize> {
        let transaction_equivalence::Delivery {
            sql,
            index,
            successful,
            before,
            after,
            ..
        } = delivery;
        if successful
            && crate::mysql::isolation::setting(sql).is_none()
            && crate::mysql::isolation::changes_isolation(sql)
        {
            if self.defaults.len() < 4096 || self.defaults.contains_key(&connection) {
                self.defaults.insert(connection, None);
            }
            self.reject_connection(connection);
            return None;
        }
        if successful && let Some((Scope::Session, level)) = crate::mysql::isolation::setting(sql) {
            if self.defaults.len() < 4096 || self.defaults.contains_key(&connection) {
                self.defaults.insert(connection, Some(level));
            }
            self.reject_connection(connection);
            return None;
        }
        if let Some(index) = index
            && let Some(profile) = self.profiles.get_mut(&index)
            && crate::mysql::isolation::setting(sql) == Some((Scope::Next, profile.plan.level))
        {
            if successful
                && before & 0x200b == 2
                && after & 0x200b == 2
                && case == Some(profile.plan.case.as_str())
            {
                profile.target = Some(connection);
                profile.phase = "pending_begin";
                profile.end_omission_proven = false;
                self.defaults
                    .entry(connection)
                    .or_insert(Some(profile.plan.baseline));
                self.bindings.insert(
                    connection,
                    Binding {
                        setup: index,
                        begun: false,
                        valid: true,
                        seen: BTreeSet::new(),
                    },
                );
            }
            return None;
        }
        let binding = self.bindings.get_mut(&connection)?;
        let profile = self.profiles.get_mut(&binding.setup)?;
        let sql = normalize_sql(sql);
        binding.valid &= successful && case == Some(profile.plan.case.as_str());
        if matches!(sql.as_str(), "begin" | "start transaction") {
            binding.valid &= !binding.begun && before & 0x200b == 2 && after & 0x200b == 3;
            binding.begun = true;
            profile.phase = if binding.valid {
                "active"
            } else {
                "invalid_begin"
            };
            return None;
        }
        let ending = matches!(sql.as_str(), "commit" | "rollback");
        // A read-only Source end is already optional under the transaction
        // owner. The Target must still really end this explicit transaction,
        // after delivering every original read on this same socket.
        let omitted_end = ending && index.is_none() && profile.plan.read_only;
        if let Some(index) = index {
            binding.valid &=
                binding.begun && profile.plan.required.contains(&index) && before & 0x200b == 3;
            binding.seen.insert(index);
        } else if !omitted_end {
            binding.valid = false;
        }
        profile.observed = binding.seen.len();
        if ending {
            let complete = index == Some(profile.plan.end) && binding.seen == profile.plan.required
                || omitted_end
                    && !binding.seen.contains(&profile.plan.end)
                    && binding.seen.len() + 1 == profile.plan.required.len()
                    && binding.seen.is_subset(&profile.plan.required);
            let covered = binding.valid
                && binding.begun
                && before & 0x200b == 3
                && after & 0x200b == 2
                && complete
                && transactions.covered_by(profile.plan.end, connection);
            profile.end_omission_proven = covered && omitted_end;
            profile.phase = if covered {
                "covered"
            } else {
                "incomplete_transaction"
            };
            let reset = covered.then_some(profile.plan.reset);
            self.bindings.remove(&connection);
            return reset;
        }
        binding.valid &= after & 0x200b == 3;
        if !binding.valid {
            profile.phase = "invalid_member";
        }
        None
    }

    pub(in crate::replay::mysql) fn reject_connection(&mut self, connection: Uuid) {
        if let Some(binding) = self.bindings.get_mut(&connection) {
            binding.valid = false;
            self.profiles.get_mut(&binding.setup).unwrap().phase = "unmatched_request";
        }
    }

    pub(in crate::replay) fn audit(&self) -> Vec<Value> {
        self.profiles.values().filter(|profile| profile.target.is_some()).map(|profile| {
            let p = &profile.plan;
            serde_json::json!({
                "kind":"mysql_next_transaction_isolation",
                "case_id":p.case, "source_connection_id":p.source_connection,
                "source_setup_sequence":p.sequence,
                "source_baseline_sequence":p.baseline_sequence,
                "source_baseline_connection_id":p.baseline_connection,
                "source_setup_index":p.setup, "source_end_index":p.end, "source_reset_index":p.reset,
                "isolation":p.level.name(), "baseline":p.baseline.name(),
                "target_connection_id":profile.target, "phase":profile.phase,
                "required_members":p.required.len(), "delivered_members":profile.observed,
                "read_only":p.read_only,
                "source_end_omission_proven":profile.end_omission_proven,
                "reset_omission_proven":profile.phase == "covered",
                "coverage_kind":"source_session_restoration_omission"
            })
        }).collect()
    }
}
