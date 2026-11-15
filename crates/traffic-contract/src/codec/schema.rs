//! Open codec declarations with compatibility constructors for existing policies.
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeMap};
use serde_json::Value;
use std::{borrow::Cow, collections::BTreeMap, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Codec {
    id: Cow<'static, str>,
    configuration: Value,
}

impl Codec {
    #[allow(non_upper_case_globals)] // Preserve existing declaration constructors.
    pub const Json: Self = Self {
        id: Cow::Borrowed("json"),
        configuration: Value::Null,
    };
    #[allow(non_upper_case_globals)]
    pub const Scalar: Self = Self {
        id: Cow::Borrowed("scalar"),
        configuration: Value::Null,
    };

    pub fn registered(id: impl Into<Cow<'static, str>>, configuration: Value) -> Result<Self> {
        let id = id.into();
        ensure!(
            !id.is_empty() && id.len() <= 128,
            "codec requires a bounded identity"
        );
        ensure!(
            configuration.is_null() || configuration.is_object(),
            "codec configuration requires named options"
        );
        ensure!(
            configuration.get("kind").is_none(),
            "codec options contain the reserved kind field"
        );
        Ok(Self { id, configuration })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn configuration(&self) -> &Value {
        &self.configuration
    }
    pub fn is_json(&self) -> bool {
        self.id == "json"
    }
}

impl Serialize for Codec {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let Some(options) = self.configuration.as_object() else {
            return serializer.serialize_str(self.id());
        };
        let mut map = serializer.serialize_map(Some(options.len() + 1))?;
        map.serialize_entry("kind", self.id())?;
        for (name, value) in options {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CodecDocument {
    Named(String),
    Options(traffic_value::Value),
}
impl<'de> Deserialize<'de> for Codec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let (id, configuration) = match CodecDocument::deserialize(deserializer)? {
            CodecDocument::Named(id) => (id, Value::Null),
            CodecDocument::Options(traffic_value::Value::Object(mut options)) => {
                let Some(traffic_value::Value::String(id)) = options.remove("kind") else {
                    return Err(serde::de::Error::custom("codec requires a kind identity"));
                };
                let configuration = if options.is_empty() {
                    Value::Null
                } else {
                    serde_json::to_value(options).map_err(serde::de::Error::custom)?
                };
                (id, configuration)
            }
            CodecDocument::Options(_) => {
                return Err(serde::de::Error::custom(
                    "codec requires a name or named options",
                ));
            }
        };
        Self::registered(id, configuration).map_err(serde::de::Error::custom)
    }
}

pub fn unique_map<'de, D, T>(deserializer: D) -> Result<BTreeMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct MapVisitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for MapVisitor<T> {
        type Value = BTreeMap<String, T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map with unique field selectors")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, T>()? {
                if values.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate selector {key:?}"
                    )));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(MapVisitor(std::marker::PhantomData))
}
