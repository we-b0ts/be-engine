//! A key's state contract composes typed native effects without a loop script.
use super::*;
use crate::policy::native::{
    RedisActivityRefreshEffect, RedisExpiryRefreshEffect, RedisReadObservationEffect,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Contract {
    get: Option<Get>,
    append: Option<Append>,
    expire: Option<Expire>,
    set: Option<Set>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Append {
    Concatenate,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Expire {
    Refresh,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Observe {
    Observe,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Transition {
    Transition,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Last {
    Last,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Nil {
    Nil,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Get {
    Observe(Observe),
    Transient(Transient),
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transient {
    transient: Vec<Nil>,
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Set {
    Transition(Transition),
    Refresh(Refresh),
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Refresh {
    reduce: Last,
    fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) enum Operation {
    Append,
    Expire,
    Get(RedisReadObservationEffect),
    Refresh(RedisActivityRefreshEffect),
}

impl Contract {
    pub(super) fn operations(self) -> Result<Vec<Behavior>> {
        ensure!(
            self.get.is_some()
                || self.append.is_some()
                || self.expire.is_some()
                || self.set.is_some(),
            "Redis state contract is empty"
        );
        let mut operations = Vec::new();
        let refreshes = matches!(self.set, Some(Set::Refresh(_)));
        if let Some(get) = self.get {
            let transient_nil = match get {
                Get::Observe(_) => false,
                Get::Transient(transient) => {
                    ensure!(
                        transient.transient.len() == 1,
                        "state.get.transient requires exactly [nil]"
                    );
                    true
                }
            };
            if refreshes {
                ensure!(
                    !transient_nil,
                    "metadata SET refresh requires delivered current-value GET; nil cannot be transient in that lifetime"
                );
                // This owner proves GET/current-SET pairs together. Splitting
                // them into two native owners would lose that causal contract.
            } else {
                operations.push(Operation::Get(RedisReadObservationEffect {
                    state_values: true,
                    transient_nil,
                }));
            }
        }
        if self.append.is_some() {
            operations.push(Operation::Append);
        }
        if self.expire.is_some() {
            operations.push(Operation::Expire);
        }
        if let Some(Set::Refresh(refresh)) = self.set {
            let Last::Last = refresh.reduce;
            ensure!(
                !refresh.fields.is_empty(),
                "state.set.reduce: last requires explicit refresh fields"
            );
            operations.push(Operation::Refresh(RedisActivityRefreshEffect {
                fields: refresh.fields,
            }));
        }
        // SET transition is ordinary finite matching, including every real write.
        Ok(operations.into_iter().map(Behavior::State).collect())
    }
}

impl Operation {
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::Append => "state.append",
            Self::Expire => "state.expire",
            Self::Get(_) => "state.get",
            Self::Refresh(_) => "state.set",
        }
    }
    pub(super) fn operation(&self) -> Option<&str> {
        match self {
            Self::Append => Some("APPEND"),
            Self::Expire => Some("EXPIRE"),
            Self::Get(_) => Some("GET"),
            Self::Refresh(_) => None,
        }
    }
    pub(super) fn effect(&self) -> NativeEffect {
        match self {
            Self::Append => NativeEffect::RedisAppendStream,
            Self::Expire => NativeEffect::RedisExpiryRefresh(RedisExpiryRefreshEffect {}),
            Self::Get(effect) => NativeEffect::RedisReadObservation(effect.clone()),
            Self::Refresh(effect) => NativeEffect::RedisActivityRefresh(effect.clone()),
        }
    }
    pub(super) fn reverse(effect: &NativeEffect) -> Option<Self> {
        Some(match effect {
            NativeEffect::RedisAppendStream => Self::Append,
            NativeEffect::RedisExpiryRefresh(_) => Self::Expire,
            NativeEffect::RedisReadObservation(effect) if effect.state_values => {
                Self::Get(effect.clone())
            }
            NativeEffect::RedisActivityRefresh(effect) => Self::Refresh(effect.clone()),
            _ => return None,
        })
    }
    pub(super) fn compact(&self, entry: &mut Mapping) -> Result<()> {
        let state = entry
            .entry("state".into())
            .or_insert_with(|| Value::Mapping(Mapping::new()))
            .as_mapping_mut()
            .context("Redis state requires a mapping")?;
        let (key, value) = match self {
            Self::Append => ("append", Value::String("concatenate".into())),
            Self::Expire => ("expire", Value::String("refresh".into())),
            Self::Get(effect) => (
                "get",
                if effect.transient_nil {
                    serde_yaml::from_str("transient: [nil]")?
                } else {
                    Value::String("observe".into())
                },
            ),
            Self::Refresh(effect) => (
                "set",
                serde_yaml::to_value(serde_json::json!({"reduce":"last", "fields":effect.fields}))?,
            ),
        };
        ensure!(
            state.insert(key.into(), value).is_none(),
            "duplicate Redis state operation owner"
        );
        Ok(())
    }
}
