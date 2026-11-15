//! Application-owned bindings reuse one semantic rule across native locations.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};

use super::*;

pub use traffic_protocol::evidence::MessageSide;

#[derive(Clone, Default)]
pub struct BindingRegistry {
    codecs: CodecRegistry,
    rules: BTreeMap<String, Arc<ValueRule>>,
    bindings: BTreeMap<String, Bindings>,
}

#[derive(Clone, Default)]
struct Bindings {
    request: Vec<RuleBinding>,
    response: Vec<RuleBinding>,
    rebase_time: BTreeSet<String>,
}

impl std::fmt::Debug for BindingRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BindingRegistry")
            .field("protocols", &self.bindings.keys().collect::<Vec<_>>())
            .field("rules", &self.rules.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl BindingRegistry {
    pub fn new(codecs: CodecRegistry) -> Self {
        Self {
            codecs,
            ..Self::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    pub fn signature(&self) -> Result<Vec<u8>> {
        let rules = self
            .rules
            .iter()
            .map(|(name, rule)| Ok((name, contract_signature(&rule.contract)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let bindings = self.bindings.iter().map(|(protocol, bindings)| {
            let describe = |values: &[RuleBinding]| values.iter().map(|binding| serde_json::json!({
                "rule":binding.rule.id,"selector":binding.selector,"codec":binding.codec,"pointer":binding.pointer
            })).collect::<Vec<_>>();
            (protocol, serde_json::json!({"request":describe(&bindings.request),"response":describe(&bindings.response),"rebase_time":bindings.rebase_time}))
        }).collect::<BTreeMap<_, _>>();
        Ok(serde_json::to_vec(
            &serde_json::json!({"rules":rules,"bindings":bindings}),
        )?)
    }

    pub fn register(
        &mut self,
        protocol: &str,
        side: MessageSide,
        binding: RuleBinding,
        rebase_time: bool,
    ) -> Result<()> {
        ensure!(
            !protocol.is_empty() && !binding.rule.id.is_empty(),
            "native binding identity is empty"
        );
        if let Some(existing) = self.rules.get(&binding.rule.id) {
            ensure!(
                existing.contract == binding.rule.contract,
                "one value rule has conflicting semantics"
            );
        }
        if rebase_time {
            ensure!(
                side == MessageSide::Response
                    && binding
                        .rule
                        .contract
                        .unconditional()
                        .time()
                        .is_some_and(|time| time.relation
                            == traffic_contract::rule::TimeRelation::PreserveOffset),
                "time rebasing requires a preserve_offset response field"
            );
        }
        traffic_contract::path::validate_pointer(&binding.pointer, true)?;
        CodecPlan::compile(&binding.codec, &self.codecs)?;
        self.rules
            .insert(binding.rule.id.clone(), binding.rule.clone());
        let bindings = self.bindings.entry(protocol.into()).or_default();
        if rebase_time {
            bindings.rebase_time.insert(binding.rule.id.clone());
        }
        match side {
            MessageSide::Request => bindings.request.push(binding),
            MessageSide::Response => bindings.response.push(binding),
        }
        Ok(())
    }

    pub fn for_protocol(&self, protocol: &str) -> crate::MessageRules {
        match self.bindings.get(protocol) {
            Some(bindings) => crate::MessageRules {
                request: bindings.request.clone(),
                response: bindings.response.clone(),
                rebase_time: bindings.rebase_time.clone(),
            },
            None => crate::MessageRules::default(),
        }
    }
}

fn contract_signature(contract: &FieldContract) -> Result<Value> {
    match contract {
        FieldContract::IdentityAnchor => Ok(serde_json::json!({"kind":"identity_anchor"})),
        FieldContract::Conditional { when, contract } => Ok(serde_json::json!({
            "kind":"conditional","when":when,"contract":contract_signature(contract)?
        })),
        FieldContract::Time { anchor, .. } | FieldContract::Duration { anchor, .. } => {
            let mut signature = serde_json::to_value(contract)?;
            signature
                .as_object_mut()
                .context("field contract has no object representation")?
                .insert("runtime_anchor".into(), serde_json::to_value(anchor)?);
            Ok(signature)
        }
        other => Ok(serde_json::to_value(other)?),
    }
}
