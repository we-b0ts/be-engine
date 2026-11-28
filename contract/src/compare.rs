//! Pure, bounded comparison of a decoded value. Protocol admission and commits
//! remain with the caller. Selected fields compose before the strict remainder.
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
};

use serde::Serialize;
use serde_json::Value;

use super::time::{self, ClockPair};
use crate::rule::{FieldContract, TimeAnchor};
mod composition;
pub mod diagnosis;
pub mod identity;
mod logical;
mod scope;
pub use identity::key as identity_key;
pub use logical::{LogicalProjection, compare_logical_all, compare_projected_logical_all};
mod native;
mod observations;
mod pointers;
mod policy;
mod walk;
pub use ValueCopyProof as TimeCopyProof;
pub use capabilities::{ExplicitRules, RegisteredRules, RuleMetadata, ValueCopyProof};
use walk::{Node, Paths};
mod capabilities;
pub use native::{
    LeafContext, LeafObservations, NativeContext, NativeField, NonceIdentity, VerifiedField,
};

const MAX_COMPARISONS: usize = 16_384;
const MAX_DEPTH: usize = 128;

type NonceRelationship = ([u8; 32], [u8; 32]);
type NonceRelationships = BTreeMap<(String, String), Vec<NonceRelationship>>;

#[derive(Debug, Clone, Copy, Default)]
pub struct AnchorClocks {
    pub case: ClockPair,
    pub dependency: ClockPair,
    pub delivery: ClockPair,
    /// Explicit response/event clocks, including an explicitly missing pair.
    /// Dependency-only adapters can retain their actual request pair above.
    pub observation: Option<ClockPair>,
}

impl AnchorClocks {
    pub fn observations(self) -> Value {
        serde_json::json!({"case":self.case,"dependency":self.dependency,
            "delivery":self.delivery,"observation":self.observation()})
    }
    pub fn for_request(case: ClockPair, dependency: ClockPair, delivery: ClockPair) -> Self {
        Self {
            case,
            dependency,
            delivery,
            observation: Some(dependency),
        }
    }

    pub fn for_response(request: ClockPair, response: ClockPair) -> Self {
        Self {
            case: request,
            observation: Some(response),
            ..Default::default()
        }
    }

    pub fn observation(self) -> ClockPair {
        self.observation.unwrap_or(self.dependency)
    }

    pub fn get(self, anchor: TimeAnchor) -> ClockPair {
        match anchor {
            TimeAnchor::Observation => self.observation(),
            TimeAnchor::DependencyRequestStart => self.dependency,
            TimeAnchor::ApiRequestStart | TimeAnchor::DependencyDelivery => ClockPair::default(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Field<'a> {
    pub rule_id: &'a str,
    pub pointer: &'a str,
    pub contract: &'a FieldContract,
}

pub use crate::comparison::Difference;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Comparison {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pre_matches: Vec<crate::hypothesis::Candidate>,
    pub evaluated: BTreeSet<String>,
    pub time_validations: BTreeMap<String, usize>,
    pub differences: Vec<Difference>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub policy_counts: BTreeMap<String, BTreeMap<String, usize>>,
    #[serde(skip)]
    pub observations: traffic_policy::Observations,
    #[serde(skip)]
    pub nonce_relationships: NonceRelationships,
    #[serde(skip)]
    pub identities: identity::Bijection,
}

impl Comparison {
    /// Tokens stay in private runtime/control data; diagnostics serialize only differences.
    pub fn identity_pairs(&self) -> Vec<crate::identity::IdentityPair> {
        self.identities.pairs().collect()
    }

    pub fn passed(&self) -> bool {
        self.differences.is_empty()
    }

    /// Conservative heap estimate for a successful comparison kept by Replay.
    /// Opaque observations, diagnostics and nonce state use the live path.
    pub fn prefetch_retained_bytes(&self) -> Option<usize> {
        if !self.passed()
            || !self.pre_matches.is_empty()
            || !self.observations.is_empty()
            || !self.nonce_relationships.is_empty()
        {
            return None;
        }
        let mut bytes = self
            .identities
            .prefetch_retained_bytes()
            .saturating_add(self.pre_matches.capacity() * size_of::<crate::hypothesis::Candidate>())
            .saturating_add(self.differences.capacity() * size_of::<Difference>())
            .saturating_add(btree_retained_bytes::<String, ()>(self.evaluated.len()))
            .saturating_add(string_map_retained_bytes(&self.time_validations))
            .saturating_add(string_map_retained_bytes(&self.policy_counts))
            .saturating_add(btree_retained_bytes::<
                (String, String),
                Vec<NonceRelationship>,
            >(0));
        for rule in &self.evaluated {
            bytes = bytes.saturating_add(rule.capacity());
        }
        for counters in self.policy_counts.values() {
            bytes = bytes.saturating_add(string_map_retained_bytes(counters));
        }
        Some(bytes)
    }

    pub fn merge_and_validate(&mut self, other: Comparison) {
        self.pre_matches.extend(other.pre_matches);
        if let Err(reason) = self.identities.merge(other.identities) {
            self.differences.push(difference("", reason));
        }
        self.evaluated.extend(other.evaluated);
        self.differences.extend(other.differences);
        for (rule_id, count) in other.time_validations {
            *self.time_validations.entry(rule_id).or_default() += count;
        }
        if let Err(error) = self.observations.merge(other.observations) {
            self.differences.push(difference("", &error.to_string()));
        }
        for (metric, values) in other.policy_counts {
            let counts = self.policy_counts.entry(metric).or_default();
            for (rule, count) in values {
                *counts.entry(rule).or_default() += count;
            }
        }
        for (scope, pairs) in other.nonce_relationships {
            let existing = self.nonce_relationships.entry(scope).or_default();
            for (source, target) in pairs {
                if existing
                    .iter()
                    .any(|(a, b)| (*a == source && *b != target) || (*b == target && *a != source))
                {
                    self.differences
                        .push(difference("", "generated binding bijection changed"));
                }
                if !existing.contains(&(source, target)) {
                    existing.push((source, target));
                }
            }
        }
    }
}

fn string_map_retained_bytes<V>(map: &BTreeMap<String, V>) -> usize {
    map.keys().fold(
        btree_retained_bytes::<String, V>(map.len()),
        |bytes, key| bytes.saturating_add(key.capacity()),
    )
}

fn btree_retained_bytes<K, V>(len: usize) -> usize {
    // Rust's B-tree nodes carry up to eleven entries and twelve edges. Charge
    // every node as internal, including a possible retained empty root. All
    // nodes below the root have at least five entries.
    let nodes = 1 + len.saturating_sub(1) / 5;
    nodes.saturating_mul(12 * size_of::<(K, V)>() + 128)
}

#[derive(Clone, Default)]
struct Decisions {
    evaluated: BTreeSet<String>,
    selected: BTreeSet<usize>,
    selected_native: BTreeSet<usize>,
    observations: traffic_policy::Observations,
    counts: BTreeMap<String, BTreeMap<String, usize>>,
    time_validations: BTreeMap<String, usize>,
    nonces: NonceRelationships,
    identities: identity::Bijection,
}

struct Comparator<'a> {
    fields: &'a [Field<'a>],
    native: &'a [NativeField<'a>],
    verified: &'a [VerifiedField<'a>],
    field_pointers: &'a pointers::Index<'a>,
    native_pointers: &'a pointers::Index<'a>,
    verified_pointers: &'a pointers::Index<'a>,
    rule_metadata: &'a dyn RuleMetadata,
    time_copies: BTreeMap<(&'a str, &'a str), Vec<&'a dyn TimeCopyProof>>,
    clocks: AnchorClocks,
    remaining: usize,
    source_root: &'a Value,
    target_root: &'a Value,
    logical_roots: Option<(&'a traffic_value::Value, &'a traffic_value::Value)>,
}

pub fn compare(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_with_native(source, target, fields, &[], clocks)
}

pub fn compare_with_native(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_with_verified(source, target, fields, native, &[], clocks)
}

pub fn compare_with_verified(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_all(
        source,
        target,
        fields,
        native,
        verified,
        clocks,
        &[],
        &ExplicitRules,
    )
}

pub fn compare_with_verified_time_copies(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    copies: &[&dyn TimeCopyProof],
) -> Comparison {
    compare_all(
        source,
        target,
        fields,
        &[],
        verified,
        clocks,
        copies,
        &ExplicitRules,
    )
}

pub fn compare_with_time_copies(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
    copies: &[&dyn TimeCopyProof],
) -> Comparison {
    compare_all(
        source,
        target,
        fields,
        &[],
        &[],
        clocks,
        copies,
        &ExplicitRules,
    )
}

#[allow(clippy::too_many_arguments)] // One transaction owns rules, leaves, clocks and delivered-value proofs.
pub fn compare_all(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    time_copies: &[&dyn TimeCopyProof],
    rule_metadata: &dyn RuleMetadata,
) -> Comparison {
    compare_inputs(
        source,
        target,
        fields,
        native,
        verified,
        clocks,
        time_copies,
        rule_metadata,
        None,
    )
}

#[allow(clippy::too_many_arguments)] // The optional typed roots preserve codec scalar categories beside legacy adapters.
fn compare_inputs(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    time_copies: &[&dyn ValueCopyProof],
    rule_metadata: &dyn RuleMetadata,
    logical_roots: Option<(&traffic_value::Value, &traffic_value::Value)>,
) -> Comparison {
    let mut remaining = MAX_COMPARISONS;
    if std::ptr::eq(source, target)
        && fields.is_empty()
        && native.is_empty()
        && verified.is_empty()
        && time_copies.is_empty()
        && within_comparison_budget(source, &mut remaining, 0)
    {
        return Comparison::default();
    }
    let field_pointers = pointers::Index::new(fields.iter().map(|field| field.pointer));
    let native_pointers = pointers::Index::new(native.iter().map(|field| field.pointer));
    let verified_pointers = pointers::Index::new(verified.iter().map(|field| field.pointer));
    let mut comparator = Comparator {
        rule_metadata,
        fields,
        native,
        verified,
        field_pointers: &field_pointers,
        native_pointers: &native_pointers,
        verified_pointers: &verified_pointers,
        time_copies: time_copies
            .iter()
            .fold(BTreeMap::new(), |mut index, proof| {
                index.entry(proof.scope()).or_default().push(*proof);
                index
            }),
        clocks,
        remaining: MAX_COMPARISONS,
        source_root: source,
        target_root: target,
        logical_roots,
    };
    let mut decisions = Decisions::default();
    let result = comparator
        .node(
            Node {
                projected: source,
                logical: logical_roots.map(|(source, _)| source),
            },
            Node {
                projected: target,
                logical: logical_roots.map(|(_, target)| target),
            },
            &mut Paths::default(),
            &mut decisions,
            0,
        )
        .and_then(|()| {
            if let Some(missing) = fields.iter().enumerate().find(|(index, field)| {
                !decisions.selected.contains(index) && pointer_observed(source, field.pointer)
            }) {
                return Err(difference(
                    missing.1.pointer,
                    "selected field was not observed",
                ));
            }
            if let Some((_, missing)) = native
                .iter()
                .map(|field| field.pointer)
                .chain(verified.iter().map(|field| field.pointer))
                .enumerate()
                .find(|(index, pointer)| {
                    !decisions.selected_native.contains(index) && pointer_observed(source, pointer)
                })
            {
                return Err(difference(
                    missing,
                    "selected native field was not observed",
                ));
            }
            Ok(())
        });
    let mut policy_counts = decisions.counts;
    for (rule, count) in policy_counts.remove("time_validations").unwrap_or_default() {
        *decisions.time_validations.entry(rule).or_default() += count;
    }
    Comparison {
        pre_matches: Vec::new(),
        evaluated: decisions.evaluated,
        time_validations: decisions.time_validations,
        differences: result.err().into_iter().collect(),
        observations: decisions.observations,
        policy_counts,
        nonce_relationships: decisions.nonces,
        identities: decisions.identities,
    }
}

fn within_comparison_budget(value: &Value, remaining: &mut usize, depth: usize) -> bool {
    if depth > MAX_DEPTH || *remaining == 0 {
        return false;
    }
    *remaining -= 1;
    match value {
        Value::Array(values) => values
            .iter()
            .all(|value| within_comparison_budget(value, remaining, depth + 1)),
        Value::Object(fields) => fields
            .values()
            .all(|value| within_comparison_budget(value, remaining, depth + 1)),
        _ => true,
    }
}

fn difference(pointer: &str, reason: &str) -> Difference {
    Difference {
        pointer: pointer.into(),
        reason: reason.into(),
    }
}

/// A Source shape with no selected leaf leaves the entire value exact.
pub fn pointer_observed(root: &Value, pattern: &str) -> bool {
    fn visit<'a>(root: &Value, mut segments: impl Iterator<Item = &'a str> + Clone) -> bool {
        let Some(segment) = segments.next() else {
            return true;
        };
        if segment == "*" {
            root.as_array()
                .is_some_and(|values| values.iter().any(|value| visit(value, segments.clone())))
        } else {
            pointer_child(root, segment).is_some_and(|value| visit(value, segments))
        }
    }
    visit(root, pattern.split('/').skip(1))
}

fn pointer_child<'a>(root: &'a Value, segment: &str) -> Option<&'a Value> {
    match root {
        Value::Object(fields) if segment.contains('~') => {
            fields.get(&segment.replace("~1", "/").replace("~0", "~"))
        }
        Value::Object(fields) => fields.get(segment),
        Value::Array(values) if !segment.starts_with('+') => {
            if segment.len() > 1 && segment.starts_with('0') {
                return None;
            }
            values.get(segment.parse::<usize>().ok()?)
        }
        _ => None,
    }
}

fn pointer_matches(pattern: &str, pointer: &str, root: &Value) -> bool {
    if pattern == pointer {
        return true;
    }
    if !pattern.contains('*') {
        return false;
    }
    if pattern.split('/').count() != pointer.split('/').count() {
        return false;
    }
    let mut parent = Some(root);
    for (a, b) in pattern.split('/').skip(1).zip(pointer.split('/').skip(1)) {
        if a != b
            && !(a == "*"
                && parent.is_some_and(Value::is_array)
                && b.parse::<usize>().is_ok()
                && (b == "0" || !b.starts_with('0')))
        {
            return false;
        }
        parent = parent.and_then(|parent| pointer_child(parent, b));
    }
    true
}

fn escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

impl Comparator<'_> {
    fn equal_values(&self, source: Node<'_>, target: Node<'_>) -> bool {
        if self.logical_roots.is_some() {
            source.logical.is_some() && source.logical == target.logical
        } else {
            source.projected == target.projected
        }
    }

    fn node(
        &mut self,
        source_node: Node<'_>,
        target_node: Node<'_>,
        paths: &mut Paths,
        decisions: &mut Decisions,
        depth: usize,
    ) -> Result<(), Difference> {
        let (pointer, target_pointer) = paths.pair();
        let (source, target) = (source_node.projected, target_node.projected);
        if depth > MAX_DEPTH || self.remaining == 0 {
            return Err(difference(pointer, "contract comparison limit exceeded"));
        }
        self.remaining -= 1;
        let selected = self.field_pointers.matching(pointer, self.source_root);
        let native = self.native_pointers.matching(pointer, self.source_root);
        let verified = self.verified_pointers.matching(pointer, self.source_root);
        if selected.len() + native.len() + verified.len() > 1 {
            if selected.is_empty()
                && native.is_empty()
                && !source.is_array()
                && !source.is_object()
                && verified.iter().any(|&index| {
                    self.rule_metadata
                        .permits_scalar_composition(self.verified[index].rule_id)
                })
                && verified
                    .iter()
                    .filter(|&&index| {
                        !self
                            .rule_metadata
                            .permits_scalar_composition(self.verified[index].rule_id)
                    })
                    .count()
                    <= 1
            {
                let mut staged = decisions.clone();
                for &index in verified.iter() {
                    let field = &self.verified[index];
                    native::verify(
                        field,
                        LeafContext {
                            source,
                            target,
                            source_pointer: pointer,
                            target_pointer,
                            source_root: self.source_root,
                            target_root: self.target_root,
                            clocks: self.clocks,
                        },
                        &mut staged,
                    )?;
                    staged.selected_native.insert(self.native.len() + index);
                    staged.evaluated.insert(field.rule_id.into());
                }
                *decisions = staged;
                return Ok(());
            }
            if selected.len() == 1
                && self
                    .rule_metadata
                    .permits_scalar_composition(self.fields[selected[0]].rule_id)
                && !source.is_array()
                && !source.is_object()
                && (!native.is_empty() || !verified.is_empty())
            {
                return self.global_native_leaf(
                    LeafContext {
                        source,
                        target,
                        source_pointer: pointer,
                        target_pointer,
                        source_root: self.source_root,
                        target_root: self.target_root,
                        clocks: self.clocks,
                    },
                    (source_node, target_node),
                    selected[0],
                    &native,
                    &verified,
                    decisions,
                );
            }
            if native.is_empty()
                && verified.is_empty()
                && selected.iter().all(|&index| {
                    policy::compatible(
                        self.fields[selected[0]].contract,
                        self.fields[index].contract,
                        self.rule_metadata.policies(),
                    )
                })
            {
                let mut inactive = false;
                for &index in selected.iter() {
                    if let FieldContract::Conditional { when, .. } = self.fields[index].contract {
                        inactive |= !when
                            .matches_pair(
                                self.source_root,
                                self.target_root,
                                pointer,
                                target_pointer,
                            )
                            .map_err(|_| {
                                difference(pointer, "field condition branch changed or is invalid")
                            })?;
                    }
                }
                if inactive {
                    if !self.equal_values(source_node, target_node) {
                        return Err(difference(
                            pointer,
                            "inactive field contract requires exact equality",
                        ));
                    }
                    for &index in selected.iter() {
                        decisions.selected.insert(index);
                        decisions
                            .evaluated
                            .insert(self.fields[index].rule_id.into());
                    }
                    return Ok(());
                }
                for &index in selected.iter() {
                    let field = &self.fields[index];
                    decisions.selected.insert(index);
                    decisions.evaluated.insert(field.rule_id.into());
                    let definition = field
                        .contract
                        .unconditional()
                        .registered_definition(self.rule_metadata.accepts_exact_time(field.rule_id))
                        .expect("compatible registered declaration");
                    self.registered_policy(
                        &definition,
                        field,
                        source_node,
                        target_node,
                        pointer,
                        target_pointer,
                        decisions,
                        depth,
                    )?;
                }
                return Ok(());
            }
            return Err(difference(pointer, "conflicting field contracts"));
        }
        if let Some(&index) = verified.first() {
            let field = &self.verified[index];
            decisions.selected_native.insert(self.native.len() + index);
            decisions.evaluated.insert(field.rule_id.into());
            return native::verify(
                field,
                LeafContext {
                    source,
                    target,
                    source_pointer: pointer,
                    target_pointer,
                    source_root: self.source_root,
                    target_root: self.target_root,
                    clocks: self.clocks,
                },
                decisions,
            );
        }
        if let Some(&index) = native.first() {
            let field = &self.native[index];
            decisions.selected_native.insert(index);
            decisions.evaluated.insert(field.rule_id.into());
            return native::compare(source, target, field, pointer, self.clocks, decisions);
        }
        if let Some(&index) = selected.first() {
            let field = &self.fields[index];
            decisions.selected.insert(index);
            decisions.evaluated.insert(field.rule_id.into());
            let contract = if let FieldContract::Conditional { when, contract } = field.contract {
                if !when
                    .matches_pair(self.source_root, self.target_root, pointer, target_pointer)
                    .map_err(|_| {
                        difference(
                            pointer,
                            "field condition is absent, invalid, or changed on Target",
                        )
                    })?
                {
                    return if self.equal_values(source_node, target_node) {
                        Ok(())
                    } else {
                        Err(difference(
                            pointer,
                            "inactive field contract requires exact equality",
                        ))
                    };
                }
                contract.as_ref()
            } else {
                field.contract
            };
            if let Some(definition) =
                contract.registered_definition(self.rule_metadata.accepts_exact_time(field.rule_id))
            {
                return self.registered_policy(
                    &definition,
                    field,
                    source_node,
                    target_node,
                    pointer,
                    target_pointer,
                    decisions,
                    depth,
                );
            }
            match contract {
                FieldContract::Exact => {
                    return if self.equal_values(source_node, target_node) {
                        Ok(())
                    } else {
                        Err(difference(
                            pointer,
                            "exact field contract requires equal values",
                        ))
                    };
                }
                FieldContract::IdentityAnchor => {
                    if !self.equal_values(source_node, target_node) {
                        return Err(difference(pointer, "exact identity value changed"));
                    }
                    return decisions
                        .identities
                        .observe(source, target)
                        .map_err(|reason| difference(pointer, reason));
                }
                FieldContract::Conditional { .. } => {
                    return Err(difference(
                        pointer,
                        "nested field conditions are unsupported",
                    ));
                }
                FieldContract::Unordered
                | FieldContract::Identity { .. }
                | FieldContract::Time { .. }
                | FieldContract::Policy(_)
                | FieldContract::Duration { .. } => {
                    unreachable!("registered definitions execute through the policy port")
                }
            }
        }
        if self.logical_roots.is_some() {
            let (source, target) = (source_node.logical, target_node.logical);
            let scalar = |value: Option<&traffic_value::Value>| {
                value.is_some_and(|value| {
                    !matches!(
                        value,
                        traffic_value::Value::Array(_) | traffic_value::Value::Object(_)
                    )
                })
            };
            if scalar(source) || scalar(target) {
                if source.is_some() && source == target {
                    return Ok(());
                }
                if let (
                    Some(traffic_value::Value::String(source)),
                    Some(traffic_value::Value::String(target)),
                ) = (source, target)
                {
                    return self.unselected_text(source, target, pointer, decisions);
                }
                return Err(difference(pointer, "unselected value or type changed"));
            }
        }
        match (source, target) {
            (Value::Object(source), Value::Object(target)) => {
                let shared_map = std::ptr::eq(source, target);
                if !shared_map {
                    if let Some(key) = source.keys().find(|key| !target.contains_key(*key)) {
                        return Err(difference(
                            &format!("{pointer}/{}", escape(key)),
                            "field presence changed",
                        ));
                    }
                    if let Some(key) = target.keys().find(|key| !source.contains_key(*key)) {
                        return Err(difference(
                            &format!("{pointer}/{}", escape(key)),
                            "unexpected field",
                        ));
                    }
                }
                let shared_node = shared_map && source_node.shares_logical_with(target_node);
                for (key, value) in source {
                    paths.at_key(key, |paths| {
                        let source_child = source_node.object_child(value, key);
                        let target_child = if shared_node {
                            source_child
                        } else {
                            let projected = if shared_map {
                                value
                            } else {
                                target.get(key).ok_or_else(|| {
                                    difference(paths.pair().0, "field presence changed")
                                })?
                            };
                            target_node.object_child(projected, key)
                        };
                        self.node(source_child, target_child, paths, decisions, depth + 1)
                    })?;
                }
            }
            (Value::Array(source), Value::Array(target)) => {
                if source.len() != target.len() {
                    return Err(difference(pointer, "array cardinality changed"));
                }
                let shared_node =
                    std::ptr::eq(source, target) && source_node.shares_logical_with(target_node);
                for (index, (source, target)) in source.iter().zip(target).enumerate() {
                    paths.at_index(index, |paths| {
                        let source_child = source_node.array_child(source, index);
                        let target_child = if shared_node {
                            source_child
                        } else {
                            target_node.array_child(target, index)
                        };
                        self.node(source_child, target_child, paths, decisions, depth + 1)
                    })?;
                }
            }
            _ if source == target && same_type(source, target) => (),
            (Value::String(source), Value::String(target)) => {
                return self.unselected_text(source, target, pointer, decisions);
            }
            _ => return Err(difference(pointer, "unselected value or type changed")),
        }
        Ok(())
    }

    fn unselected_text(
        &self,
        source: &str,
        target: &str,
        pointer: &str,
        decisions: &mut Decisions,
    ) -> Result<(), Difference> {
        let Some((rule_id, observed)) =
            self.rule_metadata
                .compare_unselected_text(source, target, self.clocks)
        else {
            return Err(difference(pointer, "unselected value or type changed"));
        };
        native::observe(rule_id, pointer, observed, decisions)?;
        decisions.evaluated.insert(rule_id.into());
        Ok(())
    }
}

pub use traffic_time::declaration::{core_format, parse_time_pair, parse_time_value};

fn same_type(source: &Value, target: &Value) -> bool {
    std::mem::discriminant(source) == std::mem::discriminant(target)
        && (!source.is_number() || time::validate_numeric_category(source, target).is_ok())
}

#[cfg(test)]
fn test_compare(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_all(
        source,
        target,
        fields,
        &[],
        &[],
        clocks,
        &[],
        &RegisteredRules(traffic_extensions::policies()),
    )
}

#[cfg(test)]
#[test]
fn exact_same_reference_keeps_the_comparison_budget_and_diagnostic() {
    let source = Value::Array(vec![Value::Null; MAX_COMPARISONS - 1]);
    assert!(compare(&source, &source, &[], AnchorClocks::default()).passed());
    let source = Value::Array(vec![Value::Null; MAX_COMPARISONS]);
    let result = compare(&source, &source, &[], AnchorClocks::default());
    assert_eq!(result.differences.len(), 1);
    assert_eq!(
        result.differences[0].pointer,
        format!("/{}", MAX_COMPARISONS - 1)
    );
    assert_eq!(
        result.differences[0].reason,
        "contract comparison limit exceeded"
    );
}

#[cfg(test)]
#[test]
fn prefetch_estimate_includes_identity_tokens_and_requires_success() {
    let mut result = Comparison::default();
    let before = result.prefetch_retained_bytes().unwrap();
    let source = Value::String("recorded-token".repeat(16));
    let target = Value::String("delivered-token".repeat(16));
    result.identities.observe(&source, &target).unwrap();
    assert!(
        result.prefetch_retained_bytes().unwrap()
            >= before + source.as_str().unwrap().len() + target.as_str().unwrap().len()
    );
    result.differences.push(difference("", "failed"));
    assert!(result.prefetch_retained_bytes().is_none());
}
