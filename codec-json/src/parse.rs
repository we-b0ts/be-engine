//! Strict JSON decoding: duplicate object members must not be silently discarded.
mod numbers;
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::fmt;
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(v)) = a.next_element()? {
                    values.push(v);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some((k, Strict(v))) = a.next_entry::<String, Strict>()? {
                    if values.insert(k, v).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        d.deserialize_any(JsonVisitor)
    }
}
pub fn parse(bytes: &[u8]) -> Option<Value> {
    parse_with_limit(bytes, crate::MAX_VALUE_BYTES)
}
pub fn parse_with_limit(bytes: &[u8], limit: usize) -> Option<Value> {
    decode::<Strict>(bytes, limit).map(|value| value.0)
}

pub(super) fn parse_logical(bytes: &[u8]) -> Option<traffic_value::Value> {
    // The logical value's visitor also rejects duplicate object members.
    decode(bytes, crate::MAX_VALUE_BYTES)
}

fn decode<T: de::DeserializeOwned>(bytes: &[u8], limit: usize) -> Option<T> {
    if bytes.len() > limit {
        return None;
    }
    if !numbers::preserves_decimal_tokens(bytes) {
        return None;
    }
    serde_json::from_slice(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_logical_decode_matches_the_serde_projection() {
        let bytes = br#"{"values":[-9223372036854775808,18446744073709551615,1.00,-0,-0.0,1e3,null,"\u0061"]}"#;
        let expected: traffic_value::Value = serde_json::from_value(parse(bytes).unwrap()).unwrap();
        let translated = parse_logical(bytes).unwrap();
        assert_eq!(translated, expected);
        for index in [3, 4] {
            let path = format!("/values/{index}");
            assert!(matches!(
                translated.pointer(&path),
                Some(traffic_value::Value::Number(traffic_value::Number::Float(value)))
                    if value.is_sign_negative()
            ));
        }
        assert!(parse_logical(br#"{"k":1,"\u006b":2}"#).is_none());
        assert!(parse_logical(b"9007199254740993.0").is_none());
    }
}
