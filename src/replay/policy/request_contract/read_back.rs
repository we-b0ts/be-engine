//! Explicit delivery references to already validated Redis writes.
use super::*;
use crate::policy::native::{IdentityCapture, NativeRule, RedisReadBack};
use crate::policy::{Database, NativeEffect, Protocol, Resource, Slot, Surface};
use crate::policy_evidence::{
    SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata,
};
use serde::Serialize;
mod state;
mod wire;
use state::Binding;
pub(super) use state::ReadBackState;

#[derive(Debug, Clone, Default)]
pub(in crate::replay) struct ReadBackWrite(Vec<Binding>);

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct RedisReadBackReport {
    pub rule_id: String,
    pub case_id: String,
    pub declaration: usize,
    pub source_write_connection: uuid::Uuid,
    pub source_write_sequence: u64,
    pub source_read_connection: uuid::Uuid,
    pub source_read_sequence: u64,
    pub pointer: String,
    pub source_fingerprint: String,
    pub target_fingerprint: String,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct PreparedReadBack {
    pub response: Vec<u8>,
    original: Vec<u8>,
    metadata: WitnessMetadata,
    reports: Vec<RedisReadBackReport>,
}

impl RequestContracts {
    pub(in crate::replay::policy) fn has_read_back_for(
        &self,
        context: &RedisRequestContext<'_>,
        args: &[Vec<u8>],
    ) -> bool {
        args.first().is_some_and(|key| {
            self.read_back_rules(context, key).iter().any(|rule| {
                rule.effect.redis_read_back().iter().any(|entry| {
                    entry.contract.operation == context.command
                        || entry.contract.write_operation == context.command
                })
            })
        })
    }
    fn read_back_rules(&self, context: &RedisRequestContext<'_>, key: &[u8]) -> Vec<&NativeRule> {
        self.compiled_rules()
            .into_iter()
            .flat_map(|policy| &policy.native)
            .filter(|compiled| {
                !compiled.rule.effect.redis_read_back().is_empty()
                    && self.native_rule_scope_matches(
                        &compiled.rule.id,
                        Some(context.case),
                        Protocol::Redis,
                        context.target,
                        Some(&Database::Index(context.database)),
                        context.username,
                    )
                    && compiled.rule.selector.key.as_ref().is_some_and(|selector| {
                        super::super::native_projection::key(selector).matches(key)
                    })
            })
            .map(|compiled| &compiled.rule)
            .collect()
    }

    /// Called only after the whole request matched. Previewing candidates never
    /// publishes bindings, including candidates rejected by another contract.
    pub(in crate::replay) fn preview_redis_read_back_write(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        target: &[Vec<u8>],
        response: &[u8],
        completed: Option<DateTime<Utc>>,
    ) -> Result<ReadBackWrite> {
        let Some(key) = source.first() else {
            return Ok(ReadBackWrite::default());
        };
        let mut pending = Vec::new();
        for rule in self.read_back_rules(context, key) {
            for (index, entry) in rule
                .effect
                .redis_read_back()
                .iter()
                .enumerate()
                .filter(|(_, e)| e.contract.write_operation == context.command)
            {
                if !wire::successful_write(context.command, response)? {
                    continue;
                }
                ensure!(
                    source.len() == target.len(),
                    "read_back write arguments changed"
                );
                let read = &entry.contract;
                let indices = if context.command == "RPUSH" {
                    ensure!(source.len() <= 129, "read_back RPUSH exceeds 128 elements");
                    (read.argument_index..source.len()).collect::<Vec<_>>()
                } else {
                    vec![read.argument_index]
                };
                for argument in indices {
                    let left = source
                        .get(argument)
                        .context("read_back Source write argument missing")?;
                    let right = target
                        .get(argument)
                        .context("read_back Target write argument missing")?;
                    if !active(rule, left, Some(right))? {
                        continue;
                    }
                    for pointer in pointers(read) {
                        pending.push(Binding {
                            case: context.case.into(),
                            rule: rule.id.clone(),
                            entry: index,
                            database: context.database,
                            username: context.username.map(str::to_owned),
                            key: key.clone(),
                            target_key: target[0].clone(),
                            pointer: pointer.into(),
                            source: wire::value(left, pointer)?,
                            target: wire::value(right, pointer)?,
                            connection: context
                                .connection_id
                                .context("read_back needs original write connection identity")?,
                            sequence: context
                                .sequence
                                .context("read_back needs original write sequence")?,
                            completed: completed
                                .context("read_back needs original write completion clock")?,
                        });
                    }
                }
            }
        }
        self.state
            .lock()
            .expect("read_back")
            .read_back
            .validate(&pending)?;
        Ok(ReadBackWrite(pending))
    }

    pub(in crate::replay) fn commit_redis_read_back_write(
        &self,
        pending: ReadBackWrite,
    ) -> Result<()> {
        let mut state = self.state.lock().expect("read_back");
        state.read_back.validate(&pending.0)?;
        state.read_back.commit(pending.0);
        Ok(())
    }

    pub(in crate::replay) fn prepare_redis_read_back(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        target: &[Vec<u8>],
        response: &[u8],
    ) -> Result<Option<PreparedReadBack>> {
        let Some(key) = source.first() else {
            return Ok(None);
        };
        let selected = self
            .read_back_rules(context, key)
            .into_iter()
            .flat_map(|rule| {
                rule.effect
                    .redis_read_back()
                    .iter()
                    .enumerate()
                    .filter(move |(_, entry)| entry.contract.operation == context.command)
                    .map(move |(index, entry)| (rule, index, &entry.contract))
            })
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Ok(None);
        }
        ensure!(
            source.len() == target.len(),
            "read_back read arguments changed"
        );
        let state = self.state.lock().expect("read_back");
        let mut reports = Vec::new();
        let derived = wire::transform(context.command, response, |payload| {
            let original = payload.clone();
            let mut json = None;
            for (rule, index, read) in &selected {
                if !active(rule, &original, None)? {
                    continue;
                }
                for pointer in pointers(read) {
                    let value = wire::value(&original, pointer)?;
                    let binding = state.read_back.lookup(
                        context,
                        &rule.id,
                        *index,
                        (key, &target[0]),
                        pointer,
                        &value,
                    )?;
                    if pointer.is_empty() {
                        *payload = binding
                            .target
                            .as_str()
                            .context("raw read_back value must be text")?
                            .as_bytes()
                            .to_vec();
                    } else if binding.target != value {
                        let value = json.get_or_insert_with(|| {
                            crate::json_value::parse_with_limit(&original, wire::MAX_BYTES)
                                .expect("validated JSON")
                        });
                        *value
                            .pointer_mut(pointer)
                            .context("read_back response field disappeared")? =
                            binding.target.clone();
                    }
                    reports.push(RedisReadBackReport {
                        rule_id: rule.id.clone(),
                        case_id: context.case.into(),
                        declaration: *index,
                        source_write_connection: binding.connection,
                        source_write_sequence: binding.sequence,
                        source_read_connection: context
                            .connection_id
                            .context("read_back read identity missing")?,
                        source_read_sequence: context
                            .sequence
                            .context("read_back read sequence missing")?,
                        pointer: pointer.into(),
                        source_fingerprint: crate::policy_evidence::digest(&serde_json::to_vec(
                            &binding.source,
                        )?),
                        target_fingerprint: crate::policy_evidence::digest(&serde_json::to_vec(
                            &binding.target,
                        )?),
                    });
                }
            }
            if let Some(json) = json {
                *payload = serde_json::to_vec(&json)?;
            }
            Ok(())
        })?;
        if reports.is_empty() {
            return Ok(None);
        }
        drop(state);
        let clocks = self.contract_clocks(
            Some(context.case),
            context.recorded_at,
            context.actual_at,
            None,
            None,
        );
        Ok(Some(PreparedReadBack {
            response: derived,
            original: response.into(),
            reports,
            metadata: WitnessMetadata {
                surface: Surface::DependencyResponse,
                source_role: SourceRole::DependencyResponse,
                target_role: TargetRole::DerivedDelivery,
                source: SourceIdentity {
                    case_id: context.case.into(),
                    exchange_id: None,
                    connection_id: context.connection_id.map(|id| id.to_string()),
                    sequence: context.sequence,
                },
                resource: Some(Resource {
                    protocol: Protocol::Redis,
                    endpoint: crate::policy::Endpoint {
                        host: context.target.host.clone(),
                        port: context.target.port,
                    },
                    database: Some(Database::Index(context.database)),
                    username: context.username.map(str::to_owned),
                }),
                operation: context.command.into(),
                slot: Slot::Value,
                clocks: WitnessClocks {
                    case: crate::policy_evidence::ClockPair {
                        source: clocks.case.source,
                        target: clocks.case.target,
                    },
                    dependency: crate::policy_evidence::ClockPair {
                        source: clocks.dependency.source,
                        target: clocks.dependency.target,
                    },
                    delivery: Default::default(),
                },
            },
        }))
    }

    pub(in crate::replay) fn commit_redis_read_back(
        &self,
        prepared: &PreparedReadBack,
        delivered: DateTime<Utc>,
    ) -> Result<()> {
        let mut metadata = prepared.metadata.clone();
        metadata.clocks.delivery.target = Some(delivered);
        self.record_delivery_witness(
            &uuid::Uuid::new_v4().to_string(),
            metadata,
            &prepared.original,
            &prepared.response,
        )?;
        let mut state = self.state.lock().expect("read_back");
        for report in &prepared.reports {
            state
                .read_back
                .used
                .insert((report.rule_id.clone(), report.declaration));
            if state.read_back.reports.len() < 4096 {
                state.read_back.reports.push(report.clone());
            }
        }
        Ok(())
    }

    pub(in crate::replay) fn read_back_report(&self) -> Vec<RedisReadBackReport> {
        self.state
            .lock()
            .expect("read_back")
            .read_back
            .reports
            .clone()
    }

    pub(in crate::replay::policy) fn validate_read_back_coverage(
        &self,
        selected: &BTreeSet<String>,
    ) -> Result<()> {
        let state = self.state.lock().expect("read_back");
        for rule in self
            .compiled_rules()
            .into_iter()
            .flat_map(|policy| &policy.native)
            .filter(|r| selected.contains(&r.rule.id))
        {
            for index in 0..rule.rule.effect.redis_read_back().len() {
                ensure!(
                    state
                        .read_back
                        .used
                        .contains(&(rule.rule.id.clone(), index)),
                    "read_back rule {:?} declaration {index} has no positive Source write-to-read witness",
                    rule.rule.id
                );
            }
        }
        Ok(())
    }
}

fn pointers(read: &RedisReadBack) -> Vec<&str> {
    if read.json_pointers.is_empty() {
        vec![""]
    } else {
        read.json_pointers.iter().map(String::as_str).collect()
    }
}

fn active(rule: &NativeRule, source: &[u8], target: Option<&[u8]>) -> Result<bool> {
    let NativeEffect::Identity(effect) = &rule.effect else {
        return Ok(true);
    };
    let IdentityCapture::RedisArgument {
        when: Some(when),
        json_pointer: Some(pointer),
        ..
    } = &effect.capture
    else {
        return Ok(true);
    };
    let source = crate::json_value::parse_with_limit(source, wire::MAX_BYTES)
        .context("conditional read_back requires Source JSON")?;
    if let Some(target) = target {
        let target = crate::json_value::parse_with_limit(target, wire::MAX_BYTES)
            .context("conditional read_back requires Target JSON")?;
        when.matches_pair(&source, &target, pointer, pointer)
    } else {
        when.active(&source, pointer)
    }
}

#[cfg(test)]
mod tests;
