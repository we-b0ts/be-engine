//! Bounded case-local renaming shared by physical resource positions.
//! Parsing and hashing are prepared before acquiring a runtime store mutex.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::policy::{CompiledRule, FieldContract, IdentityFormat};

const MAX_CASE_ENTITIES: usize = 4096;
const MAX_RUN_ENTITIES: usize = 32768;
const MAX_PROPOSAL_PAIRS: usize = 16384;
type Fingerprint = [u8; 32];

/// Private control/runtime data. Never include tokens in diagnostic reports.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityPair {
    pub(crate) domain: String,
    pub(crate) source: String,
    pub(crate) target: String,
}

impl std::fmt::Debug for IdentityPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityPair")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct PreparedPair {
    pair: IdentityPair,
    source: Fingerprint,
    target: Fingerprint,
}

impl PreparedPair {
    fn prepare(pair: IdentityPair) -> Result<Self> {
        ensure!(
            !pair.domain.is_empty()
                && pair.domain.len() <= 64
                && pair
                    .domain
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
            "identity domain requires a bounded identifier"
        );
        ensure!(
            [&pair.source, &pair.target]
                .into_iter()
                .all(|token| !token.is_empty() && token.len() <= 256 && token.is_ascii()),
            "identity token exceeds its bounded representation"
        );
        Ok(Self {
            source: Sha256::digest(pair.source.as_bytes()).into(),
            target: Sha256::digest(pair.target.as_bytes()).into(),
            pair,
        })
    }
}

#[derive(Clone)]
pub(crate) struct IdentityDecision {
    case: String,
    pairs: Vec<PreparedPair>,
}

impl std::fmt::Debug for IdentityDecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityDecision")
            .field("pairs", &self.pairs.len())
            .finish_non_exhaustive()
    }
}

impl IdentityDecision {
    pub(crate) fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub(crate) fn prepare(case: &str, pairs: Vec<IdentityPair>) -> Result<Self> {
        ensure!(
            !case.is_empty() && case.len() <= 512,
            "invalid identity case scope"
        );
        ensure!(
            pairs.len() <= MAX_PROPOSAL_PAIRS,
            "identity proposal bound exceeded"
        );
        Ok(Self {
            case: case.to_owned(),
            pairs: pairs
                .into_iter()
                .map(PreparedPair::prepare)
                .collect::<Result<_>>()?,
        })
    }

    pub(crate) fn merge(&mut self, other: Self) -> Result<()> {
        ensure!(
            self.case == other.case,
            "identity proposals have different case scopes"
        );
        ensure!(
            self.pairs.len() + other.pairs.len() <= MAX_PROPOSAL_PAIRS,
            "identity proposal bound exceeded"
        );
        self.pairs.extend(other.pairs);
        Ok(())
    }
}

#[derive(Default)]
struct Domain {
    forward: BTreeMap<Fingerprint, (Fingerprint, String)>,
    reverse: BTreeMap<Fingerprint, Fingerprint>,
}

#[derive(Default)]
struct Case {
    domains: BTreeMap<String, Domain>,
    entities: usize,
}

#[derive(Default)]
pub(crate) struct IdentityStore {
    cases: BTreeMap<String, Case>,
    entities: usize,
}

impl std::fmt::Debug for IdentityStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityStore")
            .field("cases", &self.cases.len())
            .field("entities", &self.entities)
            .finish()
    }
}

impl IdentityStore {
    pub(crate) fn begin_case(&mut self, case: &str) {
        if let Some(case) = self.cases.remove(case) {
            self.entities -= case.entities;
        }
    }

    #[cfg(test)]
    pub(crate) fn has_case(&self, case: &str) -> bool {
        self.cases.get(case).is_some_and(|case| case.entities > 0)
    }

    /// Validate against committed bindings plus a small proposal-local overlay.
    /// No state changes are visible until `commit` validates every pair again.
    pub(crate) fn validate(&self, decision: &IdentityDecision) -> Result<()> {
        let case = self.cases.get(&decision.case);
        let mut forward = BTreeMap::new();
        let mut reverse = BTreeMap::new();
        let mut added = 0;
        for pair in &decision.pairs {
            let domain = case.and_then(|case| case.domains.get(&pair.pair.domain));
            let source = (pair.pair.domain.as_str(), pair.source);
            let target = (pair.pair.domain.as_str(), pair.target);
            ensure!(
                domain
                    .and_then(|domain| domain.forward.get(&pair.source))
                    .is_none_or(|(target, _)| target == &pair.target)
                    && domain
                        .and_then(|domain| domain.reverse.get(&pair.target))
                        .is_none_or(|source| source == &pair.source)
                    && forward
                        .get(&source)
                        .is_none_or(|target| target == &pair.target)
                    && reverse
                        .get(&target)
                        .is_none_or(|source| source == &pair.source),
                "identity binding bijection changed"
            );
            if domain.is_none_or(|domain| !domain.forward.contains_key(&pair.source))
                && !forward.contains_key(&source)
            {
                added += 1;
            }
            forward.insert(source, pair.target);
            reverse.insert(target, pair.source);
        }
        ensure!(
            case.map_or(0, |case| case.entities) + added <= MAX_CASE_ENTITIES,
            "identity binding exceeds 4096 entities per case"
        );
        ensure!(
            self.entities + added <= MAX_RUN_ENTITIES,
            "identity binding exceeds 32768 entities per replay"
        );
        Ok(())
    }

    pub(crate) fn commit(&mut self, decision: IdentityDecision) -> Result<()> {
        self.validate(&decision)?;
        if decision.pairs.is_empty() {
            return Ok(());
        }
        let case = self.cases.entry(decision.case).or_default();
        for pair in decision.pairs {
            let domain = case.domains.entry(pair.pair.domain).or_default();
            if domain.forward.contains_key(&pair.source) {
                continue;
            }
            domain
                .forward
                .insert(pair.source, (pair.target, pair.pair.target));
            domain.reverse.insert(pair.target, pair.source);
            case.entities += 1;
            self.entities += 1;
        }
        Ok(())
    }

    /// A recorded read is an input. Known entities deliver their Target token;
    /// an unknown historical entity is fixed to its delivered Source value.
    pub(crate) fn deliveries(
        &self,
        case: &str,
        selected: &[PreparedIdentityDelivery],
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        ensure!(
            !case.is_empty() && case.len() <= 512,
            "invalid identity case scope"
        );
        let domains = self.cases.get(case).map(|case| &case.domains);
        let mut values = Vec::with_capacity(selected.len());
        let mut pairs = Vec::with_capacity(selected.len());
        for selected in selected {
            let target = domains
                .and_then(|domains| domains.get(&selected.binding))
                .and_then(|domain| domain.forward.get(&selected.source_hash));
            let (target_hash, token) = target
                .map(|(hash, token)| (*hash, token.as_str()))
                .unwrap_or((selected.source_hash, selected.source.as_str()));
            values.push(if selected.numeric {
                Value::from(
                    token
                        .parse::<u64>()
                        .context("invalid numeric identity delivery")?,
                )
            } else {
                Value::String(format!("{}{token}", selected.prefix))
            });
            pairs.push(PreparedPair {
                pair: IdentityPair {
                    domain: selected.binding.clone(),
                    source: selected.source.clone(),
                    target: token.to_owned(),
                },
                source: selected.source_hash,
                target: target_hash,
            });
        }
        let decision = IdentityDecision {
            case: case.into(),
            pairs,
        };
        ensure!(
            decision.pairs.len() <= MAX_PROPOSAL_PAIRS,
            "identity delivery proposal bound exceeded"
        );
        self.validate(&decision)?;
        Ok((values, decision))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct IdentityDelivery<'a> {
    pub(crate) binding: &'a str,
    pub(crate) prefix: &'a str,
    pub(crate) format: IdentityFormat,
    pub(crate) value: &'a Value,
}

impl IdentityDelivery<'_> {
    pub(crate) fn token(self) -> Result<String> {
        super::json::identity::token(self.value, self.prefix, self.format, "")
            .map_err(|difference| anyhow::anyhow!(difference.reason))
    }
}

pub(crate) struct PreparedIdentityDelivery {
    binding: String,
    prefix: String,
    source: String,
    source_hash: Fingerprint,
    numeric: bool,
}

impl PreparedIdentityDelivery {
    pub(crate) fn prepare(selected: IdentityDelivery<'_>) -> Result<Self> {
        let source = selected.token()?;
        Ok(Self {
            binding: selected.binding.to_owned(),
            prefix: selected.prefix.to_owned(),
            source_hash: Sha256::digest(source.as_bytes()).into(),
            source,
            numeric: selected.value.is_number(),
        })
    }
}

pub(crate) struct SelectedIdentity<'a> {
    pub(crate) pointer: String,
    pub(crate) delivery: IdentityDelivery<'a>,
    pub(crate) condition: Option<&'a crate::policy::FieldCondition>,
}

pub(crate) fn rules_have_identity(rules: &[&CompiledRule]) -> bool {
    rules.iter().any(|rule| {
        rule.rule
            .contract
            .values()
            .any(|contract| matches!(contract.unconditional(), FieldContract::Identity { .. }))
    })
}

/// Select only declared, Source-active physical leaves; never scan other strings.
pub(crate) fn select<'a>(
    root: &'a Value,
    rules: &[&'a CompiledRule],
) -> Result<Vec<SelectedIdentity<'a>>> {
    select_inner(root, rules, true)
}

/// A comparison-copy projection must also preserve the exact inactive branch.
pub(crate) fn select_with_inactive<'a>(
    root: &'a Value,
    rules: &[&'a CompiledRule],
) -> Result<Vec<SelectedIdentity<'a>>> {
    select_inner(root, rules, false)
}

fn select_inner<'a>(
    root: &'a Value,
    rules: &[&'a CompiledRule],
    active_only: bool,
) -> Result<Vec<SelectedIdentity<'a>>> {
    let mut selected = Vec::new();
    let mut budget = 16384;
    for rule in rules {
        for (pattern, contract) in &rule.rule.contract {
            let FieldContract::Identity {
                binding,
                prefix,
                format,
            } = contract.unconditional()
            else {
                continue;
            };
            for pointer in selected_pointers(pattern, root, &mut budget)? {
                if active_only
                    && let FieldContract::Conditional { when, .. } = contract
                    && !when.active(root, &pointer)?
                {
                    continue;
                }
                selected.push(SelectedIdentity {
                    condition: match contract {
                        FieldContract::Conditional { when, .. } => Some(when),
                        _ => None,
                    },
                    delivery: IdentityDelivery {
                        binding,
                        prefix,
                        format: *format,
                        value: root
                            .pointer(&pointer)
                            .context("identity field disappeared")?,
                    },
                    pointer,
                });
                ensure!(
                    selected.len() <= MAX_CASE_ENTITIES,
                    "identity leaf selection bound exceeded"
                );
            }
        }
    }
    Ok(selected)
}

fn selected_pointers(pattern: &str, root: &Value, budget: &mut usize) -> Result<Vec<String>> {
    fn walk(
        parts: &[&str],
        value: &Value,
        pointer: String,
        budget: &mut usize,
        selected: &mut Vec<String>,
    ) -> Result<()> {
        ensure!(*budget > 0, "identity selector traversal bound exceeded");
        *budget -= 1;
        let Some((part, rest)) = parts.split_first() else {
            ensure!(
                selected.len() < MAX_CASE_ENTITIES,
                "identity leaf selection bound exceeded"
            );
            selected.push(pointer);
            return Ok(());
        };
        if *part == "*"
            && let Some(array) = value.as_array()
        {
            for (index, value) in array.iter().enumerate() {
                walk(rest, value, format!("{pointer}/{index}"), budget, selected)?;
            }
        } else if let Some(value) = value.pointer(&format!("/{part}")) {
            walk(rest, value, format!("{pointer}/{part}"), budget, selected)?;
        }
        Ok(())
    }
    crate::policy::validate_pointer(pattern, true)?;
    let mut selected = Vec::new();
    walk(
        &pattern.split('/').skip(1).collect::<Vec<_>>(),
        root,
        String::new(),
        budget,
        &mut selected,
    )?;
    Ok(selected)
}

#[cfg(test)]
mod tests;
