//! Request-relative time bindings for exact, finite Redis EVAL invocations.
use std::{collections::BTreeSet, sync::Arc};

use anyhow::{Result, ensure};
use serde_json::{Value, json};
use traffic_contract::{
    codec::Codec,
    rule::{FieldContract, TimeAnchor},
};
use traffic_engine_policy::policy::{CompiledPolicy, native::SequenceArgument, native_admission};
use traffic_policy_value::{RuleBinding, ValueRule};
use traffic_protocol::{connection::RecordedExchange, observation::normalize_host};
use traffic_protocol_redis::message::RequestMessage;

pub(super) fn bindings(
    policy: &CompiledPolicy,
    exchange: &RecordedExchange,
) -> Result<Option<Vec<RuleBinding>>> {
    if exchange.reference.protocol() != "redis" {
        return Ok(None);
    }
    let Some(request) = exchange
        .request()
        .and_then(|message| message.as_any())
        .and_then(|message| message.downcast_ref::<RequestMessage>())
    else {
        return Ok(None);
    };
    if !request.command.eq_ignore_ascii_case("EVAL") {
        return Ok(None);
    }
    let mut selected = BTreeSet::new();
    let mut bindings = Vec::new();
    for compiled in &policy.native {
        let rule = &compiled.rule;
        let Some(eval) = native_admission::finite_eval_time(rule) else {
            continue;
        };
        if rule.selector.resource.as_ref().is_some_and(|resource| {
            normalize_host(&resource.endpoint.host) != exchange.endpoint.host
                || resource.endpoint.port != exchange.endpoint.port
                || resource
                    .database
                    .as_ref()
                    .and_then(|db| db.index())
                    .is_some_and(|db| db != request.database)
                || resource
                    .username
                    .as_ref()
                    .is_some_and(|user| Some(user) != request.username.as_ref())
        }) || !request.matches_single_key_eval(eval.key, eval.sha256)
        {
            continue;
        }
        for (&index, argument) in &eval.command.arguments {
            ensure!(
                selected.insert(index),
                "overlapping finite Redis EVAL time rules at argument {index}"
            );
            let SequenceArgument::Time(time) = &argument.contract else {
                unreachable!("finite EVAL admission permits only scalar time contracts");
            };
            let contract = FieldContract::Time {
                format: time.format,
                relation: time.relation,
                anchor: TimeAnchor::DependencyRequestStart,
                utc_offset: time.utc_offset.clone(),
                clock_group: time.clock_group.clone(),
                clock_scope: time.clock_scope.clone(),
            };
            let mut policy = contract
                .registered_definition(false)
                .expect("time policy definition");
            policy.options["decimal_text"] = true.into();
            bindings.push(RuleBinding {
                rule: Arc::new(ValueRule {
                    id: format!("{}.arg.{index}", rule.id),
                    contract: FieldContract::Policy(policy),
                }),
                selector: json!({"kind": "argument", "index": index}),
                codec: Codec::registered("string", Value::Null)?,
                pointer: String::new(),
            });
        }
    }
    Ok((!bindings.is_empty()).then_some(bindings))
}
