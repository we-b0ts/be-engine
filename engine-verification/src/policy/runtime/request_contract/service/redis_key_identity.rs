//! Physical key captures submit complete typed identities alongside Redis values.
use std::sync::Arc;

use anyhow::Result;
use serde_json::{Value, json};
use traffic_contract::{codec::Codec, rule::FieldContract};
use traffic_engine_policy::policy::CompiledPolicy;
use traffic_policy_value::{RuleBinding, ValueRule};
use traffic_protocol::message::ProtocolMessage;
use traffic_protocol_redis::{key_slots, message::RequestMessage};

pub(super) fn bindings(
    policy: &CompiledPolicy,
    source: &dyn ProtocolMessage,
) -> Result<Vec<RuleBinding>> {
    let Some(redis) = policy
        .redis
        .as_ref()
        .filter(|redis| !redis.key_identities.is_empty())
    else {
        return Ok(Vec::new());
    };
    let Some(request) = source
        .as_any()
        .and_then(|message| message.downcast_ref::<RequestMessage>())
    else {
        return Ok(Vec::new());
    };

    let mut bindings = Vec::new();
    for index in key_slots::key_indices(&request.command.to_ascii_uppercase(), &request.args)? {
        let key = &request.args[index];
        let Some(identity) = redis.key_identity(key) else {
            continue;
        };
        let Some(value) = std::str::from_utf8(key)
            .ok()
            .and_then(|key| key.strip_prefix(identity.prefix))
            .and_then(|key| key.strip_suffix(identity.suffix))
        else {
            continue;
        };
        let contract = identity.field.select_contract_with_registry(
            &Value::String(value.into()),
            None,
            traffic_extensions::policies(),
        )?;
        if !matches!(contract, FieldContract::Identity { .. }) {
            continue;
        }
        bindings.push(RuleBinding {
            rule: Arc::new(ValueRule {
                id: format!("global.redis.key.{index}"),
                contract,
            }),
            selector: json!({"kind": "argument", "index": index}),
            codec: Codec::registered(
                "string",
                json!({"prefix": identity.prefix, "suffix": identity.suffix}),
            )?,
            pointer: String::new(),
        });
    }
    Ok(bindings)
}
