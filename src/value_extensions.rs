//! Application composition of content implementations and the Replay rule port.
use anyhow::Result;
use traffic_contract::compare::{AnchorClocks, Comparison, RuleMetadata};
use traffic_policy_value::{PreparedMessage, RuleBinding};
use traffic_protocol::message::ProtocolMessage;
use traffic_replay::rules::RuleRuntime;

pub(crate) struct ValueRules;

pub(crate) fn policy_locations(
    policy: &str,
    source: &serde_json::Value,
    target: &serde_json::Value,
    include_root: bool,
) -> Vec<String> {
    (|| {
        let policy = traffic_extensions::policies().prepare(policy, &traffic_value::Value::Null)?;
        traffic_policy_value::diagnosis::discover(
            &policy,
            &serde_json::from_value(source.clone())?,
            &serde_json::from_value(target.clone())?,
            include_root,
        )
    })()
    .unwrap_or_default()
}

pub(crate) fn normalize_policy_locations(
    policy: &str,
    source: &mut serde_json::Value,
    target: &mut serde_json::Value,
    pattern: &str,
) -> bool {
    (|| -> Result<bool> {
        let policy = traffic_extensions::policies().prepare(policy, &traffic_value::Value::Null)?;
        let mut left = serde_json::from_value(source.clone())?;
        let mut right = serde_json::from_value(target.clone())?;
        let matches =
            traffic_policy_value::diagnosis::normalize(&policy, &mut left, &mut right, pattern)?;
        *source = serde_json::to_value(left)?;
        *target = serde_json::to_value(right)?;
        Ok(matches)
    })()
    .unwrap_or(false)
}

pub(crate) fn strict_values() -> std::sync::Arc<dyn crate::replay::policy::ValueRuleHost> {
    std::sync::Arc::new(crate::value_contract::state::ValueState::default())
}

pub(crate) fn compare_registered(
    id: &str,
    options: &serde_json::Value,
    source: &serde_json::Value,
    target: &serde_json::Value,
) -> Result<traffic_policy::Evaluation> {
    let policy =
        traffic_extensions::policies().prepare(id, &serde_json::from_value(options.clone())?)?;
    policy.evaluate(
        &traffic_policy::ValuePair {
            source: &serde_json::from_value(source.clone())?,
            target: &serde_json::from_value(target.clone())?,
            source_path: "",
            target_path: "",
        },
        &mut (),
    )
}

impl RuleRuntime for ValueRules {
    type Bindings = Vec<RuleBinding>;
    type Delivery = std::collections::BTreeSet<String>;
    type Context = AnchorClocks;
    type Metadata = dyn RuleMetadata;
    type Comparison = Comparison;
    type Prepared = PreparedMessage;

    fn prepare(
        message: &dyn ProtocolMessage,
        bindings: &Vec<RuleBinding>,
    ) -> Result<PreparedMessage> {
        prepare_message(message, bindings)
    }
    fn structure(prepared: &PreparedMessage) -> &serde_json::Value {
        prepared.structure()
    }
    fn compare(
        prepared: &PreparedMessage,
        actual: &dyn ProtocolMessage,
        context: AnchorClocks,
        metadata: &Self::Metadata,
    ) -> Result<Comparison> {
        prepared.compare(actual, context, metadata)
    }
    fn passed(comparison: &Comparison) -> bool {
        comparison.passed()
    }
}

pub(crate) fn prepare_message(
    message: &dyn ProtocolMessage,
    bindings: &[RuleBinding],
) -> Result<PreparedMessage> {
    PreparedMessage::compile(message, bindings, traffic_extensions::codecs())
}

pub(crate) fn prepare_message_with_policy(
    message: &dyn ProtocolMessage,
    bindings: &[RuleBinding],
    policy: Option<std::sync::Arc<dyn traffic_policy_value::DocumentPolicy>>,
) -> Result<PreparedMessage> {
    PreparedMessage::compile_with_policy(message, bindings, policy, traffic_extensions::codecs())
}

pub(crate) fn replay_rules(
    rules: traffic_policy_value::MessageRules,
) -> traffic_replay::exchange::ExchangeRules<ValueRules> {
    traffic_replay::exchange::ExchangeRules {
        request: rules.request,
        response: rules.response,
        delivery: rules.rebase_time,
    }
}

pub(crate) fn analyze_values(
    registry: &traffic_policy::PolicyRegistry,
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    source_path: &str,
    facts: &serde_json::Value,
) -> Result<Vec<traffic_policy::Finding>> {
    let facts = serde_json::from_value(facts.clone())?;
    let evidence = ValueEvidence {
        source: Some(source),
        target: Some(target),
        source_bytes: None,
        facts: &facts,
    };
    registry.analyze(
        &traffic_policy::AnalysisInput {
            values: Some(traffic_policy::ValuePair {
                source,
                target,
                source_path,
                target_path: source_path,
            }),
            facts: &facts,
        },
        &evidence,
    )
}

pub(crate) fn analyze_source(
    registry: &traffic_policy::PolicyRegistry,
    source: &traffic_value::Value,
    bytes: &[u8],
    facts: &serde_json::Value,
) -> Result<Vec<traffic_policy::Finding>> {
    let facts = serde_json::from_value(facts.clone())?;
    registry.analyze(
        &traffic_policy::AnalysisInput {
            values: None,
            facts: &facts,
        },
        &ValueEvidence {
            source: Some(source),
            target: None,
            source_bytes: Some(bytes),
            facts: &facts,
        },
    )
}

pub(crate) fn analyze_context(
    registry: &traffic_policy::PolicyRegistry,
    facts: &serde_json::Value,
) -> Result<Vec<traffic_policy::Finding>> {
    let facts = serde_json::from_value(facts.clone())?;
    registry.analyze(
        &traffic_policy::AnalysisInput {
            values: None,
            facts: &facts,
        },
        &ValueEvidence {
            source: None,
            target: None,
            source_bytes: None,
            facts: &facts,
        },
    )
}

struct ValueEvidence<'a> {
    source: Option<&'a traffic_value::Value>,
    target: Option<&'a traffic_value::Value>,
    source_bytes: Option<&'a [u8]>,
    facts: &'a traffic_value::Value,
}

impl traffic_policy::EvidenceAccess for ValueEvidence<'_> {
    fn query(
        &self,
        kind: &str,
        selection: &traffic_value::Value,
    ) -> Result<Vec<traffic_value::Value>> {
        if kind == "source.bytes" {
            anyhow::ensure!(
                matches!(selection, traffic_value::Value::Null) || selection.as_str() == Some(""),
                "raw evidence selection requires the complete value"
            );
            let bytes = self
                .source_bytes
                .ok_or_else(|| anyhow::anyhow!("original Source bytes are unavailable"))?;
            return Ok(vec![traffic_value::Value::Bytes(bytes.to_vec())]);
        }
        let value = match kind {
            "source" => self.source,
            "target" => self.target,
            "context" => Some(self.facts),
            _ => anyhow::bail!("value analysis evidence {kind:?} is unavailable"),
        }
        .ok_or_else(|| anyhow::anyhow!("value analysis evidence {kind:?} is unavailable"))?;
        let pointer = match selection {
            traffic_value::Value::Null => "",
            traffic_value::Value::String(pointer) => pointer,
            _ => anyhow::bail!("evidence selection requires a logical pointer"),
        };
        traffic_value::path::validate(pointer, false)?;
        Ok(value.pointer(pointer).cloned().into_iter().collect())
    }
}
