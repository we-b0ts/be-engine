use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Numeric categories survive decoding independently of the original format.
#[derive(Debug, Clone, PartialEq)]
pub enum Number {
    Signed(i64),
    Unsigned(u64),
    Float(f64),
}

/// Logical values retain scalar categories and byte strings. A codec owns any
/// additional wire representation and unselected data beside this view.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
    Bytes(Vec<u8>),
}

impl Value {
    pub fn pointer(&self, pointer: &str) -> Option<&Self> {
        let mut value = self;
        if pointer.is_empty() {
            return Some(value);
        }
        for segment in pointer.strip_prefix('/')?.split('/') {
            let key = segment.replace("~1", "/").replace("~0", "~");
            value = match value {
                Self::Object(fields) => fields.get(&key)?,
                Self::Array(values) => values.get(array_index(&key)?)?,
                _ => return None,
            };
        }
        Some(value)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object(values) => Some(values),
            _ => None,
        }
    }
}

fn array_index(segment: &str) -> Option<usize> {
    if segment.is_empty()
        || !segment.bytes().all(|byte| byte.is_ascii_digit())
        || segment != "0" && segment.starts_with('0')
    {
        return None;
    }
    segment.parse().ok()
}

impl Serialize for Number {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Signed(value) => serializer.serialize_i64(*value),
            Self::Unsigned(value) => serializer.serialize_u64(*value),
            Self::Float(value) if value.is_finite() => serializer.serialize_f64(*value),
            Self::Float(_) => Err(serde::ser::Error::custom("nonfinite logical number")),
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Value;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a logical value with unique object fields")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E: de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
                Ok(Value::Number(Number::Signed(value)))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
                Ok(Value::Number(Number::Unsigned(value)))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
                if !value.is_finite() {
                    return Err(E::custom("nonfinite logical number"));
                }
                Ok(Value::Number(Number::Float(value)))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
                Ok(Value::String(value.into()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
                Ok(Value::String(value))
            }
            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Value, E> {
                Ok(Value::Bytes(value.into()))
            }
            fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Value, E> {
                Ok(Value::Bytes(value))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut fields = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if fields.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate logical field"));
                    }
                }
                Ok(Value::Object(fields))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
