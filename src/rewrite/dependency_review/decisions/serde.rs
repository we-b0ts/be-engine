//! Compact state encoding and streaming compatibility with per-occurrence state.
use super::*;
use ::serde::{
    Deserializer, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
};
use std::fmt;

const ACTIVE: &str = "dependency-decisions/v1";
const HISTORY: &str = "dependency-decision-history/v1";

fn history_groups<E: de::Error>(groups: Vec<DecisionGroup>) -> Result<Vec<Arc<DecisionGroup>>, E> {
    let mut proofs = BTreeMap::new();
    for group in &groups {
        if group.exchange_ids.is_empty() {
            return Err(E::custom("empty ownership history group"));
        }
        let key = (&group.template.proof_id, group.template.proof_revision);
        if let Some(previous) = proofs.insert(key, &group.template)
            && previous != &group.template
        {
            return Err(E::custom(
                "contradictory historical ownership templates for one proof revision",
            ));
        }
    }
    Ok(groups.into_iter().map(Arc::new).collect())
}

fn write<S: Serializer>(
    groups: &[Arc<DecisionGroup>],
    format: &str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut output = serializer.serialize_struct("OwnershipGroups", 2)?;
    output.serialize_field("format", format)?;
    output.serialize_field(
        "groups",
        &groups.iter().map(Arc::as_ref).collect::<Vec<_>>(),
    )?;
    output.end()
}
impl Serialize for DecisionSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        write(&self.groups, ACTIVE, serializer)
    }
}
impl Serialize for DecisionHistory {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        write(&self.groups, HISTORY, serializer)
    }
}

fn active_groups<E: de::Error>(groups: Vec<DecisionGroup>) -> Result<Vec<Arc<DecisionGroup>>, E> {
    let mut all = Vec::new();
    let mut templates = BTreeMap::new();
    for group in &groups {
        group.validate_active().map_err(E::custom)?;
        let key = (&group.template.proof_id, group.template.proof_revision);
        if let Some(previous) = templates.insert(key, &group.template)
            && previous != &group.template
        {
            return Err(E::custom(
                "contradictory ownership templates for one proof revision",
            ));
        }
        all.extend_from_slice(&group.exchange_ids);
    }
    all.sort_unstable();
    if all.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(E::custom(
            "one Source occurrence appears in multiple active ownership groups",
        ));
    }
    let mut merged = BTreeMap::<(String, u64), DecisionGroup>::new();
    for group in groups {
        let key = (
            group.template.proof_id.clone(),
            group.template.proof_revision,
        );
        if let Some(previous) = merged.get_mut(&key) {
            previous.exchange_ids.extend(group.exchange_ids);
            previous.exchange_ids.sort_unstable();
        } else {
            merged.insert(key, group);
        }
    }
    Ok(merged.into_values().map(Arc::new).collect())
}

struct ActiveVisitor;
impl<'de> Visitor<'de> for ActiveVisitor {
    type Value = DecisionSet;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("compact ownership groups or a legacy per-occurrence ownership map")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut format = None;
        let mut compact = None;
        let mut legacy = Vec::<DecisionGroup>::new();
        let mut indexes = BTreeMap::<(String, u64), usize>::new();
        let mut saw_legacy = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "format" => {
                    if format.is_some() {
                        return Err(de::Error::duplicate_field("format"));
                    }
                    format = Some(map.next_value::<String>()?);
                }
                "groups" => {
                    if compact.is_some() {
                        return Err(de::Error::duplicate_field("groups"));
                    }
                    compact = Some(map.next_value::<Vec<DecisionGroup>>()?);
                }
                _ => {
                    saw_legacy = true;
                    let id = Uuid::parse_str(&key).map_err(de::Error::custom)?;
                    let decision = map.next_value::<AttributionDecision>()?;
                    if id != decision.exchange_id {
                        return Err(de::Error::custom(
                            "ownership map key differs from its Source occurrence",
                        ));
                    }
                    let template = DecisionTemplate::from_decision(decision);
                    let key = (template.proof_id.clone(), template.proof_revision);
                    if let Some(index) = indexes.get(&key) {
                        if legacy[*index].template != template {
                            return Err(de::Error::custom(
                                "contradictory ownership templates for one proof revision",
                            ));
                        }
                        legacy[*index].exchange_ids.push(id);
                    } else {
                        indexes.insert(key, legacy.len());
                        legacy.push(DecisionGroup {
                            template,
                            exchange_ids: vec![id],
                        });
                    }
                }
            }
        }
        let groups = if saw_legacy {
            if format.is_some() || compact.is_some() {
                return Err(de::Error::custom(
                    "mixed compact and legacy ownership state",
                ));
            }
            for group in &mut legacy {
                group.exchange_ids.sort_unstable();
            }
            legacy
        } else if format.is_none() && compact.is_none() {
            vec![]
        } else {
            if format.as_deref() != Some(ACTIVE) {
                return Err(de::Error::custom("unsupported compact ownership format"));
            }
            compact.ok_or_else(|| de::Error::missing_field("groups"))?
        };
        Ok(DecisionSet {
            groups: active_groups(groups)?,
        })
    }
}
impl<'de> Deserialize<'de> for DecisionSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ActiveVisitor)
    }
}

struct HistoryVisitor;
impl<'de> Visitor<'de> for HistoryVisitor {
    type Value = DecisionHistory;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("compact ownership history or its original per-occurrence sequence")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut groups = Vec::<DecisionGroup>::new();
        while let Some(decision) = seq.next_element::<AttributionDecision>()? {
            let id = decision.exchange_id;
            let template = DecisionTemplate::from_decision(decision);
            if let Some(previous) = groups.last_mut().filter(|group| group.template == template) {
                previous.exchange_ids.push(id);
            } else {
                groups.push(DecisionGroup {
                    template,
                    exchange_ids: vec![id],
                });
            }
        }
        Ok(DecisionHistory {
            groups: history_groups(groups)?,
        })
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut format = None;
        let mut groups = None;
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
                _ => return Err(de::Error::unknown_field(&key, &["format", "groups"])),
            }
        }
        if format.as_deref() != Some(HISTORY) {
            return Err(de::Error::custom(
                "unsupported compact ownership history format",
            ));
        }
        let groups = groups.ok_or_else(|| de::Error::missing_field("groups"))?;
        Ok(DecisionHistory {
            groups: history_groups(groups)?,
        })
    }
}
impl<'de> Deserialize<'de> for DecisionHistory {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(HistoryVisitor)
    }
}
