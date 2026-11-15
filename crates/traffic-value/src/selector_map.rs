//! Reject duplicate ownership selectors rather than accepting last-write wins.
use std::{collections::BTreeMap, fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};

pub fn unique_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: SelectorKey,
    V: Deserialize<'de>,
{
    struct Unique<K, V>(PhantomData<(K, V)>);
    impl<'de, K, V> Visitor<'de> for Unique<K, V>
    where
        K: SelectorKey,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map with unique explicit selectors")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<SelectedKey<K>, V>()? {
                if values.insert(key.0, value).is_some() {
                    return Err(de::Error::custom("duplicate rule selector"));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Unique(PhantomData))
}

pub trait SelectorKey: Ord + Sized {
    fn deserialize_key<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>;
}

impl SelectorKey for String {
    fn deserialize_key<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)
    }
}

impl SelectorKey for usize {
    fn deserialize_key<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Index;
        impl Visitor<'_> for Index {
            type Value = usize;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-negative slot index or canonical decimal index string")
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<usize, E> {
                usize::try_from(value).map_err(|_| E::custom("slot index overflows"))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<usize, E> {
                self.visit_u64(
                    u64::try_from(value).map_err(|_| E::custom("slot index is negative"))?,
                )
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<usize, E> {
                let index: usize = value.parse().map_err(|_| E::custom("invalid slot index"))?;
                if index.to_string() != value {
                    return Err(E::custom("slot index string is not canonical"));
                }
                Ok(index)
            }
        }
        deserializer.deserialize_any(Index)
    }
}

struct SelectedKey<K>(K);
impl<'de, K: SelectorKey> Deserialize<'de> for SelectedKey<K> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        K::deserialize_key(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Deserialize)]
    struct Slots {
        #[serde(deserialize_with = "unique_map")]
        values: BTreeMap<usize, String>,
    }
    #[test]
    fn numeric_slots_accept_json_keys_and_reject_normalized_duplicates() {
        let slots: Slots = serde_json::from_str(r#"{"values":{"0":"value"}}"#).unwrap();
        assert_eq!(slots.values[&0], "value");
        let slots: Slots = serde_yaml::from_str("values: {0: value}\n").unwrap();
        assert_eq!(slots.values[&0], "value");
        for yaml in [
            "values: {0: one, '0': two}\n",
            "values: {'00': bad}\n",
            "values: {-1: bad}\n",
        ] {
            assert!(serde_yaml::from_str::<Slots>(yaml).is_err());
        }
    }
}
