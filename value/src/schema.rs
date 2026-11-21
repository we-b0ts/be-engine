//! Logical field shapes shared by value producers and policy applicability checks.
use crate::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    Null,
    Boolean,
    Number,
    String,
    Bytes,
    Object,
    Enumeration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldSchema {
    Dynamic,
    Scalar,
    Typed(ValueType),
    Sequence(Box<FieldSchema>),
}

impl FieldSchema {
    pub fn accepts_literal(&self, value: &Value) -> bool {
        matches!(
            (self, value),
            (Self::Dynamic, _)
                | (
                    Self::Scalar,
                    Value::Null
                        | Value::Bool(_)
                        | Value::Number(_)
                        | Value::String(_)
                        | Value::Bytes(_)
                )
                | (Self::Typed(ValueType::Null), Value::Null)
                | (Self::Typed(ValueType::Boolean), Value::Bool(_))
                | (Self::Typed(ValueType::Number), Value::Number(_))
                | (Self::Typed(ValueType::String), Value::String(_))
                | (Self::Typed(ValueType::Bytes), Value::Bytes(_))
                | (Self::Typed(ValueType::Object), Value::Object(_))
        )
    }
}
