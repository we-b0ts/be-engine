//! Temporal leaves become copy evidence only after the read reaches the wire.
use super::*;
use crate::value_codec::CodecPlan;
use crate::value_contract::time_copies::{self, TimeCopyLookup};
use sha2::{Digest, Sha256};
use traffic_contract::provenance::ValueOrigin;

const MAX_LEAVES: usize = 4096;
const MAX_IDENTITIES: usize = 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct RedisTimeRead<'a> {
    pub host: &'a str,
    pub port: u16,
    pub database: i64,
    pub command: &'a str,
    pub source_args: &'a [Vec<u8>],
    pub target_args: &'a [Vec<u8>],
    pub source_response: &'a [u8],
    pub delivered_response: &'a [u8],
}

#[derive(Clone, Debug)]
struct Leaf {
    pattern: Arc<str>,
    pointer: String,
    value: Value,
    time: Arc<crate::policy::TimeContract>,
}

#[derive(Clone, Debug)]
struct ReadValue {
    ordinal: usize,
    container: crate::policy::RedisContainer,
    key: Vec<u8>,
    hash_field: Option<Vec<u8>>,
    payload_digest: [u8; 32],
    plan: ReadPlan,
    leaves: Vec<Leaf>,
}

#[derive(Clone, Debug)]
enum ReadPlan {
    Json(Arc<CodecPlan>),
    Scalar(traffic_policy_value::scalar::ScalarDecoder),
}

fn prepare_global_values(
    command: &str,
    source_args: &[Vec<u8>],
    source: &[u8],
    global: &crate::policy::CompiledJsonPolicy,
    redis: Option<&crate::policy::RedisPolicy>,
    clocks: crate::value_contract::json::AnchorClocks,
) -> Result<Vec<ReadValue>> {
    let values = redis_field_values(command, source_args, Some(source))?;
    let mut prepared = Vec::new();
    let mut leaf_count = 0usize;
    let mut identity_bytes = 0usize;
    for (ordinal, value) in values.iter().enumerate() {
        let Some(payload) = value.payload else {
            continue;
        };
        let (logical, scalar_decoder) = if let Some(logical) = crate::json_value::parse(payload) {
            (logical, None)
        } else if redis
            .map(|policy| policy.field(value.key))
            .transpose()?
            .flatten()
            .is_none()
            && let Some(scalar) =
                crate::value_contract::redis_scalar::decode_automatic(payload, global, clocks)?
        {
            let decoder = scalar.decoder();
            (scalar.logical, Some(decoder))
        } else {
            continue;
        };
        let leaves = time_copies::global_leaves(&logical, global, clocks)?
            .into_iter()
            .map(|leaf| Leaf {
                pattern: Arc::from(leaf.pattern),
                pointer: leaf.pointer,
                value: leaf.value,
                time: Arc::new(leaf.time),
            })
            .collect::<Vec<_>>();
        if leaves.is_empty() {
            continue;
        }
        leaf_count += leaves.len();
        identity_bytes += value.key.len() + value.hash_field.map_or(0, <[u8]>::len);
        ensure!(
            leaf_count <= MAX_LEAVES && identity_bytes <= MAX_IDENTITIES,
            "Redis pending time read exceeds its bounded capacity"
        );
        prepared.push(ReadValue {
            ordinal,
            container: value.container,
            key: value.key.to_vec(),
            hash_field: value.hash_field.map(<[u8]>::to_vec),
            payload_digest: Sha256::digest(payload).into(),
            plan: match scalar_decoder {
                Some(decoder) => ReadPlan::Scalar(decoder),
                None => ReadPlan::Json(Arc::new(crate::value_codec::compile(
                    &crate::policy::Codec::Json,
                )?)),
            },
            leaves,
        });
    }
    Ok(prepared)
}

fn prepare_scalar_values(
    command: &str,
    source_args: &[Vec<u8>],
    source: &[u8],
    policy: &crate::policy::RedisPolicy,
    settings: &crate::policy::TimePolicy,
    clocks: crate::value_contract::json::AnchorClocks,
) -> Result<Vec<ReadValue>> {
    use crate::value_contract::redis_scalar;
    let values = redis_field_values(command, source_args, Some(source))?;
    let mut prepared = Vec::new();
    let mut count = 0usize;
    let mut identities = 0usize;
    for (ordinal, value) in values.iter().enumerate() {
        let Some(payload) = value.payload else {
            continue;
        };
        let Some(field) = policy.field(value.key)? else {
            continue;
        };
        let Some(scalar) = redis_scalar::decode_field(payload, field)? else {
            continue;
        };
        let leaves = time_copies::global_leaves(
            &scalar.logical,
            &redis_scalar::plan(field, settings),
            clocks,
        )?
        .into_iter()
        .map(|leaf| Leaf {
            pattern: Arc::from(leaf.pattern),
            pointer: leaf.pointer,
            value: leaf.value,
            time: Arc::new(leaf.time),
        })
        .collect::<Vec<_>>();
        if leaves.is_empty() {
            continue;
        }
        count += leaves.len();
        identities += value.key.len() + value.hash_field.map_or(0, <[u8]>::len);
        ensure!(
            count <= MAX_LEAVES && identities <= MAX_IDENTITIES,
            "Redis pending scalar time read exceeds its bounded capacity"
        );
        prepared.push(ReadValue {
            ordinal,
            container: value.container,
            key: value.key.to_vec(),
            hash_field: value.hash_field.map(<[u8]>::to_vec),
            payload_digest: Sha256::digest(payload).into(),
            plan: ReadPlan::Scalar(scalar.decoder()),
            leaves,
        });
    }
    Ok(prepared)
}

pub(crate) fn redis_delivered_scalar_time_copies(
    read: RedisTimeRead<'_>,
    policy: &crate::policy::RedisPolicy,
    settings: &crate::policy::TimePolicy,
    clocks: crate::value_contract::json::AnchorClocks,
    record: &mut CopyRecorder<'_>,
) -> Result<usize> {
    let target = TargetKey {
        host: read.host.into(),
        port: read.port,
    };
    let values = prepare_scalar_values(
        read.command,
        read.source_args,
        read.source_response,
        policy,
        settings,
        clocks,
    )?;
    record_values(
        &target,
        read.database,
        read.command,
        read.target_args,
        read.delivered_response,
        &values,
        record,
    )
}

pub(super) fn redis_scalar_time_write_lookups(
    position: ValueOrigin,
    source: &crate::value_contract::redis_scalar::Scalar,
    field: &crate::policy::GlobalField,
    settings: &crate::policy::TimePolicy,
    clocks: crate::value_contract::json::AnchorClocks,
) -> Result<Vec<TimeCopyLookup>> {
    Ok(time_copies::global_leaves(
        &source.logical,
        &crate::value_contract::redis_scalar::plan(field, settings),
        clocks,
    )?
    .into_iter()
    .filter_map(|leaf| {
        TimeCopyLookup::new_time(
            &leaf.time,
            position,
            position,
            &leaf.pattern,
            &leaf.pattern,
            &leaf.value,
            if leaf.rule_id == crate::policy::GLOBAL_JSON_ID {
                crate::policy::GLOBAL_REDIS_ID
            } else {
                leaf.rule_id
            },
        )
        .map(|lookup| lookup.at(&leaf.pointer, &leaf.pattern))
    })
    .collect())
}

type CopyRecorder<'a> = dyn FnMut(
        ValueOrigin,
        ValueOrigin,
        &str,
        &str,
        &Value,
        &Value,
        &crate::policy::TimeContract,
    ) -> Result<()>
    + 'a;

fn record_values(
    target: &TargetKey,
    database: i64,
    command: &str,
    target_args: &[Vec<u8>],
    delivered: &[u8],
    values: &[ReadValue],
    record: &mut CopyRecorder<'_>,
) -> Result<usize> {
    if values.is_empty() {
        return Ok(0);
    }
    let actual = redis_field_values(command, target_args, Some(delivered))?;
    let mut recorded = 0;
    for value in values {
        let Some(after) = actual.get(value.ordinal) else {
            continue;
        };
        let Some(payload) = after.payload else {
            continue;
        };
        if value.container != after.container || value.hash_field.as_deref() != after.hash_field {
            continue;
        }
        let decoded = if <[u8; 32]>::from(Sha256::digest(payload)) == value.payload_digest {
            None
        } else {
            Some(match &value.plan {
                ReadPlan::Json(plan) => plan.decode(payload)?.logical,
                ReadPlan::Scalar(decoder) => decoder.decode(payload)?,
            })
        };
        let source_position = traffic_protocol_redis::values::ValuePosition {
            host: &target.host,
            port: target.port,
            database,
            key: &value.key,
            container: value.container,
            hash_field: value.hash_field.as_deref(),
        }
        .origin();
        let target_position = redis_time_position(&target.host, target.port, database, after);
        for leaf in &value.leaves {
            let observed = match &decoded {
                Some(decoded) => decoded.pointer(&leaf.pointer),
                None => Some(&leaf.value),
            };
            let Some(observed) = observed else {
                continue;
            };
            crate::value_contract::json::parse_time_pair(&leaf.value, observed, &leaf.time)?;
            record(
                source_position,
                target_position,
                &leaf.pattern,
                &leaf.pattern,
                &leaf.value,
                observed,
                &leaf.time,
            )?;
            recorded += 1;
        }
    }
    Ok(recorded)
}

pub(crate) fn redis_delivered_global_time_copies(
    read: RedisTimeRead<'_>,
    plan: &crate::policy::CompiledJsonPolicy,
    redis: Option<&crate::policy::RedisPolicy>,
    clocks: crate::value_contract::json::AnchorClocks,
    record: &mut CopyRecorder<'_>,
) -> Result<usize> {
    let target = TargetKey {
        host: read.host.into(),
        port: read.port,
    };
    let values = prepare_global_values(
        read.command,
        read.source_args,
        read.source_response,
        plan,
        redis,
        clocks,
    )?;
    record_values(
        &target,
        read.database,
        read.command,
        read.target_args,
        read.delivered_response,
        &values,
        record,
    )
}

pub(crate) fn redis_time_position<'a>(
    host: &'a str,
    port: u16,
    database: i64,
    value: &RedisFieldValue<'a>,
) -> ValueOrigin {
    traffic_protocol_redis::values::ValuePosition {
        host,
        port,
        database,
        key: value.key,
        container: value.container,
        hash_field: value.hash_field,
    }
    .origin()
}

pub(super) fn redis_global_time_write_lookups(
    position: ValueOrigin,
    source: &crate::value_codec::DecodedValue,
    global: &crate::policy::CompiledJsonPolicy,
    clocks: crate::value_contract::json::AnchorClocks,
) -> Result<Vec<TimeCopyLookup>> {
    Ok(time_copies::global_leaves(&source.logical, global, clocks)?
        .into_iter()
        .filter_map(|leaf| {
            TimeCopyLookup::new_time(
                &leaf.time,
                position,
                position,
                &leaf.pattern,
                &leaf.pattern,
                &leaf.value,
                leaf.rule_id,
            )
            .map(|lookup| lookup.at(&leaf.pointer, &leaf.pattern))
        })
        .collect())
}
