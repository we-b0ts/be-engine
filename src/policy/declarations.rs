//! Resource-owned data positions retain their authoring graph until compilation.
use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::{Mapping, Value};

use super::{
    Codec, Delivery, FieldContract, KeySelector, RedisContainer, Resource, SourceCondition,
    SseSelector,
};
use crate::MysqlTableSeries;

#[cfg(test)]
mod field_refs_tests;
#[cfg(test)]
mod tests;

/// A partial proof inherits only within its own resource/response subtree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationProof {
    #[serde(
        default,
        deserialize_with = "optional_source",
        skip_serializing_if = "Option::is_none"
    )]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldReference {
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldReferenceUse {
    pub path: Vec<String>,
    pub reference: FieldReference,
    pub clock_group: Option<String>,
}

fn optional_source<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    super::proof::deserialize_source(d).map(Some)
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResourceDeclaration {
    pub resource: Resource,
    pub proof: Option<DeclarationProof>,
    pub tables: BTreeMap<String, MysqlTableDeclaration>,
    pub keys: Vec<RedisKeyDeclaration>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlTableDeclaration {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub table_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_series: Option<MysqlTableSeries>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<DeclarationProof>,
    #[serde(deserialize_with = "super::strict_map::unique_map")]
    pub fields: BTreeMap<String, ColumnDeclaration>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ColumnDeclaration {
    Scalar {
        field: DeclaredContract,
        delivery: Option<Delivery>,
    },
    Decoded(PayloadDeclaration),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisKeyDeclaration {
    pub key: KeySelector,
    pub container: RedisContainer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_field: Option<KeySelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<DeclarationProof>,
    pub value: PayloadDeclaration,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadDeclaration {
    pub codec: Codec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<DeclarationProof>,
    #[serde(deserialize_with = "super::strict_map::unique_map")]
    pub fields: BTreeMap<String, DeclaredContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Delivery>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDeclaration {
    pub api: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<DeclarationProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<SourceCondition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<PayloadDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sse: Vec<SseDeclaration>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SseDeclaration {
    pub event: SseSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<DeclarationProof>,
    pub codec: Codec,
    #[serde(deserialize_with = "super::strict_map::unique_map")]
    pub fields: BTreeMap<String, DeclaredContract>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeclaredContract {
    pub contract: FieldContract,
    pub proof: Option<DeclarationProof>,
}

impl<'de> Deserialize<'de> for DeclaredContract {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut value = Value::deserialize(d)?;
        let proof = value
            .as_mapping_mut()
            .and_then(|m| m.remove("proof"))
            .map(serde_yaml::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?;
        super::authoring::transform_field(&mut value, false).map_err(serde::de::Error::custom)?;
        let contract = serde_yaml::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self { contract, proof })
    }
}

impl Serialize for DeclaredContract {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut value = serde_yaml::to_value(&self.contract).map_err(serde::ser::Error::custom)?;
        super::authoring::transform_field(&mut value, true).map_err(serde::ser::Error::custom)?;
        if let Some(proof) = &self.proof {
            if !value.is_mapping() {
                value = serde_yaml::to_value(&self.contract).map_err(serde::ser::Error::custom)?;
            }
            value
                .as_mapping_mut()
                .expect("field contract mapping")
                .insert(
                    "proof".into(),
                    serde_yaml::to_value(proof).map_err(serde::ser::Error::custom)?,
                );
        }
        value.serialize(s)
    }
}

impl<'de> Deserialize<'de> for ColumnDeclaration {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut value = Value::deserialize(d)?;
        if value.get("codec").is_some() {
            return serde_yaml::from_value(value)
                .map(Self::Decoded)
                .map_err(serde::de::Error::custom);
        }
        let delivery = value
            .as_mapping_mut()
            .and_then(|m| m.remove("delivery"))
            .map(serde_yaml::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?;
        let field = serde_yaml::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self::Scalar { field, delivery })
    }
}

impl Serialize for ColumnDeclaration {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Decoded(payload) => payload.serialize(s),
            Self::Scalar { field, delivery } => {
                let mut value = serde_yaml::to_value(field).map_err(serde::ser::Error::custom)?;
                if let Some(delivery) = delivery {
                    value
                        .as_mapping_mut()
                        .ok_or_else(|| {
                            serde::ser::Error::custom("scalar delivery needs a contract mapping")
                        })?
                        .insert(
                            "delivery".into(),
                            serde_yaml::to_value(delivery).map_err(serde::ser::Error::custom)?,
                        );
                }
                value.serialize(s)
            }
        }
    }
}

impl<'de> Deserialize<'de> for ResourceDeclaration {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = Mapping::deserialize(d)?;
        let proof = map
            .remove("proof")
            .map(serde_yaml::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?;
        let tables = map
            .remove("tables")
            .map(serde_yaml::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let keys = map
            .remove("keys")
            .map(serde_yaml::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let resource =
            serde_yaml::from_value(Value::Mapping(map)).map_err(serde::de::Error::custom)?;
        Ok(Self {
            resource,
            proof,
            tables,
            keys,
        })
    }
}

impl Serialize for ResourceDeclaration {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut value = serde_yaml::to_value(&self.resource).map_err(serde::ser::Error::custom)?;
        let map = value.as_mapping_mut().expect("resource mapping");
        if let Some(proof) = &self.proof {
            map.insert(
                "proof".into(),
                serde_yaml::to_value(proof).map_err(serde::ser::Error::custom)?,
            );
        }
        if !self.tables.is_empty() {
            map.insert(
                "tables".into(),
                serde_yaml::to_value(&self.tables).map_err(serde::ser::Error::custom)?,
            );
        }
        if !self.keys.is_empty() {
            map.insert(
                "keys".into(),
                serde_yaml::to_value(&self.keys).map_err(serde::ser::Error::custom)?,
            );
        }
        value.serialize(s)
    }
}
