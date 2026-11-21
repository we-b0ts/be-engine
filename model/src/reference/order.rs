//! Total ordering lets finite inventories retain open native reference fields.
use std::cmp::Ordering;

use serde_json::Value;

use super::ProtocolRef;

impl PartialOrd for ProtocolRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProtocolRef {
    fn cmp(&self, other: &Self) -> Ordering {
        self.protocol.cmp(&other.protocol).then_with(|| {
            self.identity
                .iter()
                .map(|(key, value)| (key, OrderedValue(value)))
                .cmp(
                    other
                        .identity
                        .iter()
                        .map(|(key, value)| (key, OrderedValue(value))),
                )
        })
    }
}

#[derive(PartialEq)]
struct OrderedValue<'a>(&'a Value);

impl Eq for OrderedValue<'_> {}

impl PartialOrd for OrderedValue<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedValue<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.0, other.0) {
            (Value::Null, Value::Null) => Ordering::Equal,
            (Value::Bool(left), Value::Bool(right)) => left.cmp(right),
            (Value::Number(left), Value::Number(right)) => {
                let kind = left.is_f64().cmp(&right.is_f64());
                if kind != Ordering::Equal {
                    return kind;
                }
                if left.is_f64() {
                    return left
                        .as_f64()
                        .partial_cmp(&right.as_f64())
                        .expect("JSON numbers are finite");
                }
                let integer = |number: &serde_json::Number| {
                    number
                        .as_i64()
                        .map(i128::from)
                        .or_else(|| number.as_u64().map(i128::from))
                };
                integer(left).cmp(&integer(right))
            }
            (Value::String(left), Value::String(right)) => left.cmp(right),
            (Value::Array(left), Value::Array(right)) => left
                .iter()
                .map(OrderedValue)
                .cmp(right.iter().map(OrderedValue)),
            (Value::Object(left), Value::Object(right)) => left
                .iter()
                .map(|(key, value)| (key, OrderedValue(value)))
                .cmp(right.iter().map(|(key, value)| (key, OrderedValue(value)))),
            (left, right) => rank(left).cmp(&rank(right)),
        }
    }
}

fn rank(value: &Value) -> u8 {
    match value {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::Number(_) => 2,
        Value::String(_) => 3,
        Value::Array(_) => 4,
        Value::Object(_) => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeSet;

    #[test]
    fn open_reference_order_preserves_complete_native_identity() {
        let refs = [
            json!({"stream":"orders", "offset":17, "partition":[1,"a"]}),
            json!({"partition":[1,"a"], "offset":17, "stream":"orders"}),
            json!({"stream":"orders", "offset":18, "partition":[1,"a"]}),
            json!({"stream":"orders", "offset":17, "partition":[1,"b"]}),
        ]
        .into_iter()
        .map(|identity| ProtocolRef::new("custom", identity).unwrap())
        .collect::<BTreeSet<_>>();
        assert_eq!(refs.len(), 3);
        for reference in refs {
            let persisted = serde_json::to_vec(&reference).unwrap();
            let restored: ProtocolRef = serde_json::from_slice(&persisted).unwrap();
            assert_eq!(reference.cmp(&restored), Ordering::Equal);
        }
    }

    #[test]
    fn numeric_order_agrees_with_json_equality() {
        let values = [
            json!(-1),
            json!(-0.0),
            json!(0.0),
            json!(0),
            json!(1),
            json!(1.0),
            json!(u64::MAX),
            json!(u64::MAX - 1),
        ];
        for left in &values {
            for right in &values {
                assert_eq!(
                    OrderedValue(left).cmp(&OrderedValue(right)) == Ordering::Equal,
                    left == right
                );
                for third in &values {
                    if OrderedValue(left) <= OrderedValue(right)
                        && OrderedValue(right) <= OrderedValue(third)
                    {
                        assert!(OrderedValue(left) <= OrderedValue(third));
                    }
                }
            }
        }
    }
}
