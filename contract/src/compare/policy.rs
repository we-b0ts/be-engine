//! Adapt legacy field declarations to registered comparison policies.
use std::borrow::Cow;

use super::*;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use traffic_policy::{Evaluation, EvaluationHost, ValuePair};

struct PolicyHost<'a, 'rules> {
    comparator: &'a mut Comparator<'rules>,
    decisions: &'a mut Decisions,
    pointer: &'a str,
    target_pointer: &'a str,
    projected_source: &'a Value,
    projected_target: &'a Value,
    rule_id: &'a str,
    pattern: &'a str,
    descriptor: traffic_policy::PolicyDescriptor,
    depth: usize,
    checkpoints: Vec<(u64, Decisions)>,
    generation: u64,
}

impl Comparator<'_> {
    #[allow(clippy::too_many_arguments)] // A policy preserves both locations and the enclosing transaction.
    pub(super) fn registered_policy(
        &mut self,
        definition: &traffic_policy::PolicyDefinition,
        field: &Field<'_>,
        source: Node<'_>,
        target: Node<'_>,
        pointer: &str,
        target_pointer: &str,
        decisions: &mut Decisions,
        depth: usize,
    ) -> std::result::Result<(), Difference> {
        let policy = self
            .rule_metadata
            .policies()
            .prepare_definition(definition)
            .map_err(|error| difference(pointer, &error.to_string()))?;
        let (logical_source, logical_target) = if self.logical_roots.is_some() {
            (
                source
                    .logical
                    .map(Cow::Borrowed)
                    .ok_or_else(|| difference(pointer, "logical Source value is absent"))?,
                target
                    .logical
                    .map(Cow::Borrowed)
                    .ok_or_else(|| difference(target_pointer, "logical Target value is absent"))?,
            )
        } else {
            (
                traffic_value::Value::deserialize(source.projected)
                    .map(Cow::Owned)
                    .map_err(|error| difference(pointer, &error.to_string()))?,
                traffic_value::Value::deserialize(target.projected)
                    .map(Cow::Owned)
                    .map_err(|error| difference(pointer, &error.to_string()))?,
            )
        };
        let pair = ValuePair {
            source: &logical_source,
            target: &logical_target,
            source_path: pointer,
            target_path: target_pointer,
        };
        let mut staged = decisions.clone();
        let mut host = PolicyHost {
            comparator: self,
            decisions: &mut staged,
            pointer,
            target_pointer,
            projected_source: source.projected,
            projected_target: target.projected,
            rule_id: field.rule_id,
            pattern: field.pointer,
            descriptor: policy.descriptor().clone(),
            depth,
            checkpoints: Vec::new(),
            generation: 0,
        };
        let evaluation = policy
            .evaluate(&pair, &mut host)
            .map_err(|error| difference(pointer, &error.to_string()))?;
        if !host.checkpoints.is_empty() {
            return Err(difference(
                pointer,
                "registered policy left an open checkpoint",
            ));
        }
        if evaluation.passed() {
            for (metric, count) in evaluation.counts {
                *staged
                    .counts
                    .entry(metric)
                    .or_default()
                    .entry(field.rule_id.into())
                    .or_default() += count;
            }
            *decisions = staged;
            return Ok(());
        }
        let reason = evaluation
            .differences
            .first()
            .map(|difference| difference.summary.as_str())
            .unwrap_or("registered policy evaluation is incomplete");
        Err(difference(pointer, reason))
    }
}

impl PolicyHost<'_, '_> {
    fn take_checkpoint(&mut self, checkpoint: u64) -> Result<Decisions> {
        ensure!(
            self.checkpoints.last().map(|(id, _)| *id) == Some(checkpoint),
            "policy checkpoint is stale or out of order"
        );
        Ok(self
            .checkpoints
            .pop()
            .context("policy checkpoint disappeared")?
            .1)
    }
}

impl EvaluationHost for PolicyHost<'_, '_> {
    fn relate(&mut self, pair: &ValuePair<'_>) -> Result<()> {
        let source = crate::codec::project_value(pair.source)?;
        let target = if std::ptr::eq(pair.source, pair.target) {
            Cow::Borrowed(&source)
        } else {
            Cow::Owned(crate::codec::project_value(pair.target)?)
        };
        self.decisions
            .identities
            .observe(&source, &target)
            .map_err(|reason| anyhow::anyhow!(reason))
    }
    fn observe(&mut self, state: Box<dyn traffic_policy::ObservationState>) -> Result<()> {
        self.decisions.observations.observe(&self.descriptor, state)
    }
    fn scope(&mut self, scope: &traffic_policy::ValueScope) -> Result<traffic_policy::ScopeKey> {
        scope::resolve(
            self.comparator,
            self.pattern,
            scope,
            self.pointer,
            self.target_pointer,
            self.decisions,
        )
        .map_err(|error| anyhow::anyhow!(error.reason))
    }
    fn permits_copy(&self, requirement: &traffic_value::Value) -> Result<bool> {
        Ok(self
            .comparator
            .time_copies
            .get(&(self.rule_id, self.pointer))
            .into_iter()
            .flatten()
            .any(|proof| {
                proof.permits_value(
                    self.rule_id,
                    self.pointer,
                    self.target_pointer,
                    self.projected_source,
                    self.projected_target,
                    requirement,
                )
            }))
    }
    fn facts(&self) -> Result<traffic_value::Value> {
        Ok(serde_json::from_value(serde_json::json!({
            "clocks":self.comparator.clocks.observations(),
            "binding":{"id":self.rule_id,"pattern":self.pattern},
        }))?)
    }
    fn has_descendant_rules(&self) -> bool {
        let parent_segments = self.pointer.split('/').count();
        self.comparator
            .fields
            .iter()
            .map(|field| field.pointer)
            .chain(self.comparator.native.iter().map(|field| field.pointer))
            .chain(self.comparator.verified.iter().map(|field| field.pointer))
            .any(|pattern| {
                let segments = pattern.split('/').collect::<Vec<_>>();
                segments.len() > parent_segments
                    && pointer_matches(
                        &segments[..parent_segments].join("/"),
                        self.pointer,
                        self.comparator.source_root,
                    )
            })
    }
    fn checkpoint(&mut self) -> Result<u64> {
        self.generation = self
            .generation
            .checked_add(1)
            .context("policy checkpoint generation exhausted")?;
        self.checkpoints
            .push((self.generation, self.decisions.clone()));
        Ok(self.generation)
    }
    fn rollback(&mut self, checkpoint: u64) -> Result<()> {
        *self.decisions = self.take_checkpoint(checkpoint)?;
        Ok(())
    }
    fn accept(&mut self, checkpoint: u64) -> Result<()> {
        self.take_checkpoint(checkpoint)?;
        Ok(())
    }
    fn compare(&mut self, source_path: &str, target_path: &str) -> Result<Evaluation> {
        let (logical_source, logical_target) = match self.comparator.logical_roots {
            Some((source, target)) => {
                let source = source.pointer(source_path);
                let target = target.pointer(target_path);
                ensure!(
                    source.is_some() && target.is_some(),
                    "policy child is absent from the logical documents"
                );
                (source, target)
            }
            None => (None, None),
        };
        let source_root = self.comparator.source_root;
        let target_root = self.comparator.target_root;
        let source = source_root
            .pointer(source_path)
            .context("policy Source child disappeared")?;
        let target = target_root
            .pointer(target_path)
            .context("policy Target child disappeared")?;
        Ok(
            match self.comparator.node(
                Node {
                    projected: source,
                    logical: logical_source,
                },
                Node {
                    projected: target,
                    logical: logical_target,
                },
                &mut Paths::new(source_path, target_path),
                self.decisions,
                self.depth + 1,
            ) {
                Ok(()) => Evaluation::matched(),
                Err(error) => Evaluation::mismatch(
                    &ValuePair {
                        source: &traffic_value::Value::Null,
                        target: &traffic_value::Value::Null,
                        source_path: &error.pointer,
                        target_path,
                    },
                    "child_contract",
                    &error.reason,
                ),
            },
        )
    }
    fn budget_remaining(&self) -> bool {
        self.comparator.remaining > 0
    }
}

pub(super) fn compatible(
    left: &FieldContract,
    right: &FieldContract,
    policies: &traffic_policy::PolicyRegistry,
) -> bool {
    fn definition(contract: &FieldContract) -> Option<traffic_policy::PolicyDefinition> {
        match contract {
            FieldContract::Conditional { when, contract } if when.relative_pointer == "." => {
                definition(contract)
            }
            FieldContract::Conditional { .. } => None,
            contract => contract.registered_definition(false),
        }
    }
    let (Some(left), Some(right)) = (definition(left), definition(right)) else {
        return false;
    };
    policies.compatible(&left, &right).unwrap_or(false)
}

#[cfg(test)]
mod compatibility_tests;
