//! Application policy bindings for shared derived-value delivery.
use crate::ExecutionContext;
use anyhow::Result;
use serde_json::Value;
use traffic_contract::compare::AnchorClocks;
use traffic_contract::rule::ValueRule;

pub use traffic_contract::delivery::{select, shift, value_quantum};

pub fn materialize<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &Value,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Value> {
    let fields = rules
        .iter()
        .flat_map(|rule| {
            rule.binding()
                .delivery_time
                .iter()
                .map(
                    move |(pointer, contract)| traffic_contract::delivery::TimeField {
                        rule_id: rule.binding().id,
                        pointer,
                        contract,
                    },
                )
        })
        .collect::<Vec<_>>();
    traffic_contract::delivery::materialize(source, &fields, clocks, context.metadata)
}
