//! Inline compatibility on read; normal state saves publish only ordered references.
use super::*;
use crate::dependency::attribution::AttributionDecision;
use ::serde::{
    Deserializer, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
};
use std::fmt;

const INLINE: &str = "dependency-decision-history/v1";
const ARCHIVED: &str = "dependency-decision-history/v2";

impl Serialize for DecisionHistory {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let archived = !self.archives.is_empty() || self.origins.iter().any(Option::is_some);
        let mut output =
            serializer.serialize_struct("OwnershipHistory", if archived { 4 } else { 2 })?;
        output.serialize_field("format", if archived { ARCHIVED } else { INLINE })?;
        output.serialize_field(
            "groups",
            &self.groups.iter().map(Arc::as_ref).collect::<Vec<_>>(),
        )?;
        if archived {
            output.serialize_field("archives", &self.archives)?;
            output.serialize_field("origins", &self.origins)?;
        }
        output.end()
    }
}

pub struct HistoryVisitor;
impl<'de> Visitor<'de> for HistoryVisitor {
    type Value = DecisionHistory;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("archived ownership references, compact inline history or a legacy sequence")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut history = DecisionHistory::default();
        while let Some(decision) = seq.next_element::<AttributionDecision>()? {
            let id = decision.exchange_id;
            let template = DecisionTemplate::from_decision(decision);
            if let Some(group) = history
                .groups
                .last_mut()
                .filter(|group| group.template == template)
            {
                Arc::make_mut(group).exchange_ids.push(id);
            } else {
                history.groups.push(Arc::new(DecisionGroup {
                    template,
                    exchange_ids: vec![id],
                }));
            }
        }
        history.validate().map_err(de::Error::custom)?;
        Ok(history)
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut format = None;
        let mut groups = None;
        let mut archives = None;
        let mut origins = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "format" => {
                    if format.is_some() {
                        return Err(de::Error::duplicate_field("format"));
                    }
                    format = Some(map.next_value::<String>()?);
                }
                "groups" => {
                    if groups.is_some() {
                        return Err(de::Error::duplicate_field("groups"));
                    }
                    groups = Some(map.next_value::<Vec<DecisionGroup>>()?);
                }
                "archives" => {
                    if archives.is_some() {
                        return Err(de::Error::duplicate_field("archives"));
                    }
                    archives = Some(map.next_value::<Vec<HistoryArchiveRef>>()?);
                }
                "origins" => {
                    if origins.is_some() {
                        return Err(de::Error::duplicate_field("origins"));
                    }
                    origins = Some(map.next_value::<Vec<Option<HistoryOrigin>>>()?);
                }
                _ => {
                    return Err(de::Error::unknown_field(
                        &key,
                        &["format", "groups", "archives", "origins"],
                    ));
                }
            }
        }
        match format.as_deref() {
            Some(INLINE) if archives.is_none() && origins.is_none() => {}
            Some(ARCHIVED) if archives.is_some() && origins.is_some() => {}
            _ => {
                return Err(de::Error::custom(
                    "unsupported or mixed ownership history format",
                ));
            }
        }
        let history = DecisionHistory {
            groups: groups
                .ok_or_else(|| de::Error::missing_field("groups"))?
                .into_iter()
                .map(Arc::new)
                .collect(),
            archives: archives.unwrap_or_default(),
            origins: origins.unwrap_or_default(),
        };
        history.validate().map_err(de::Error::custom)?;
        Ok(history)
    }
}
impl<'de> Deserialize<'de> for DecisionHistory {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(HistoryVisitor)
    }
}
