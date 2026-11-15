//! Source-proven request identities fence notification admission, not wire I/O.
use super::super::*;
use crate::policy::{CompiledJsonPolicy, FieldContract, IdentityFormat};
use crate::value_contract::identities::IdentityDelivery;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(in crate::protocols::replay::redis::pubsub) struct Producers {
    case: String,
    members: usize,
    entries: BTreeMap<[u8; 32], (DateTime<Utc>, usize)>,
}

#[derive(Clone)]
struct Selected {
    source: Value,
    prefix: String,
    format: IdentityFormat,
}

#[derive(Clone)]
pub(super) struct Predecessor {
    index: usize,
    identity: Selected,
}

impl Predecessor {
    pub(super) fn ready(&self, redis: &RedisReplayState, case: &str) -> Result<bool> {
        let source = &self.identity.source;
        let (values, _) = redis.request_contracts.identity_deliveries(
            case,
            &[IdentityDelivery {
                prefix: &self.identity.prefix,
                format: self.identity.format,
                value: source,
            }],
        )?;
        if redis
            .request_contracts
            .knows_identity_value(case, source, &values[0])?
        {
            return Ok(true);
        }
        // Admission commits identity proposals before claiming the request.
        // A producer with no accepted identity cannot license a historical input.
        ensure!(
            redis.exchanges[self.index].status.is_available(),
            "notification identity producer ended without establishing its identity"
        );
        Ok(false)
    }
}

pub(super) fn predecessors(
    redis: &mut RedisReplayState,
    case: &str,
    timestamp: Option<DateTime<Utc>>,
    source: &Value,
) -> Result<Vec<Predecessor>> {
    let Some(timestamp) = timestamp else {
        return Ok(vec![]);
    };
    let Some(global) = redis.request_contracts.global_json() else {
        return Ok(vec![]);
    };
    let identities = selected(global, source)?;
    if identities.is_empty() {
        return Ok(vec![]);
    }
    let members = redis.candidates.case_members(case);
    if redis
        .pubsub
        .value_producers
        .as_ref()
        .is_none_or(|index| index.case != case || index.members != members.len())
    {
        let mut entries = BTreeMap::new();
        for &index in members.iter() {
            let exchange = &redis.exchanges[index];
            let record = &exchange.record;
            if exchange.source != ReplaySource::Case
                || exchange.case_id.as_deref() != Some(case)
                || !record.native.command.eq_ignore_ascii_case("PUBLISH")
                || !record.native.replay_safe
                || record.native.outcome != DependencyExchangeOutcome::Response
                || record.native.response_kind != "integer"
                || exchange.args.len() != 2
            {
                continue;
            }
            let Some(started) = record.started_at() else {
                continue;
            };
            let Ok(decoded) = crate::value_codec::CodecView::decode(
                &crate::policy::Codec::Json,
                &exchange.args[1],
            ) else {
                continue;
            };
            for identity in selected(global, &decoded.logical)? {
                let key = fingerprint(&identity.source)?;
                let entry = entries.entry(key).or_insert((started, index));
                if started < entry.0 {
                    *entry = (started, index);
                }
                ensure!(
                    entries.len() <= 65_536,
                    "notification producer identity index bound exceeded"
                );
            }
        }
        redis.pubsub.value_producers = Some(Producers {
            case: case.into(),
            members: members.len(),
            entries,
        });
    }
    let index = redis
        .pubsub
        .value_producers
        .as_ref()
        .expect("prepared producer index");
    let mut predecessors = Vec::new();
    for identity in identities {
        if let Some(&(started, index)) = index.entries.get(&fingerprint(&identity.source)?)
            && started < timestamp
        {
            predecessors.push(Predecessor { index, identity });
        }
    }
    Ok(predecessors)
}

fn fingerprint(value: &Value) -> Result<[u8; 32]> {
    let key = crate::value_contract::json::identity_key(value, "")
        .map_err(|difference| anyhow::anyhow!(difference.reason))?;
    Ok(Sha256::digest(key.as_bytes()).into())
}

fn selected(global: &CompiledJsonPolicy, source: &Value) -> Result<Vec<Selected>> {
    let mut values = Vec::new();
    for (pointer, field) in global.identity_fields(source)? {
        if let FieldContract::Identity { prefix, format } = field
            && let Some(source) = source.pointer(&pointer)
        {
            values.push(Selected {
                source: source.clone(),
                prefix,
                format,
            });
        }
    }
    for (_, document) in crate::value_contract::global_protocol::template::selected(global, source)?
    {
        for (name, field) in document.fields() {
            values.push(Selected {
                source: document.logical[name].clone(),
                prefix: field.prefix.clone(),
                format: field.format,
            });
        }
    }
    ensure!(
        values.len() <= 4096,
        "notification identity leaf bound exceeded"
    );
    Ok(values)
}
