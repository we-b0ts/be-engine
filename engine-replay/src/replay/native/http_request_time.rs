//! Built-in comparison for the HTTP signing date against dependency request clocks.
use std::sync::Arc;

use anyhow::Result;
use serde_json::{Value, json};
use traffic_contract::{
    codec::Codec,
    compare::AnchorClocks,
    rule::{FieldContract, TimeAnchor, TimeRelation, TimestampFormat},
};
use traffic_policy_value::{RuleBinding, ValueRule};
use traffic_protocol::message::ProtocolMessage;

pub(super) fn binding(
    source: &dyn ProtocolMessage,
    clocks: AnchorClocks,
    selected: &[RuleBinding],
) -> Result<Option<RuleBinding>> {
    if clocks.dependency.source.is_none()
        || traffic_protocol_http::request_sigv4::amz_date(source).is_none()
    {
        return Ok(None);
    }
    let selector = json!({"kind": "header", "name": "x-amz-date", "index": 0});
    let locations = source.locate(&selector)?;
    for rule in selected {
        if source
            .locate(&rule.selector)?
            .iter()
            .any(|location| locations.contains(location))
        {
            return Ok(None);
        }
    }
    let time = FieldContract::Time {
        format: TimestampFormat::AmzDate,
        relation: TimeRelation::PreserveOffset,
        anchor: TimeAnchor::DependencyRequestStart,
        utc_offset: None,
        clock_group: None,
        clock_scope: Default::default(),
    };
    Ok(Some(RuleBinding {
        rule: Arc::new(ValueRule {
            id: "builtin.http.x-amz-date".into(),
            contract: FieldContract::Policy(
                time.registered_definition(false).expect("time policy"),
            ),
        }),
        selector,
        codec: Codec::registered("string", Value::Null)?,
        pointer: String::new(),
    }))
}

#[cfg(test)]
mod tests;
