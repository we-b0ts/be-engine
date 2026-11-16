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

pub(crate) use traffic_policy_value::diagnosis::analysis::{
    analyze_context, analyze_source, analyze_values,
};
