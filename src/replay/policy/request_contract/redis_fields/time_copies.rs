//! Temporal leaves become copy evidence only after the read reaches the wire.
use super::*;
use crate::policy::{Slot, Surface};
use crate::value_codec::CodecPlan;
use crate::value_contract::time_copies::{self, TimeCopyLookup, TimeCopyPosition, TimeCopyRecord};
use sha2::{Digest, Sha256};

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
    Scalar { json: bool },
}

/// Pending reads keep small temporal leaves and identities, never JSON bodies.
#[derive(Clone, Debug)]
pub(in crate::replay) struct PreparedRedisTimeRead {
    owner: RequestContracts,
    case: String,
    target: TargetKey,
    database: i64,
    source_completed: Option<DateTime<Utc>>,
    command: String,
    target_args: Vec<Vec<u8>>,
    values: Vec<ReadValue>,
    witness: Option<crate::policy_evidence::WitnessMetadata>,
    observation: uuid::Uuid,
}

impl PreparedRedisTimeRead {
    /// Publish without awaiting the global ReplayState lock. Other connections
    /// see all of this successfully delivered read's temporal pairs together.
    pub(in crate::replay) fn publish(
        &self,
        delivered: &[u8],
        completed: DateTime<Utc>,
    ) -> Result<()> {
        let mut records = Vec::new();
        let redis_get = self
            .values
            .first()
            .filter(|_| self.command == "GET")
            .map(|value| value.payload_digest);
        record_values(
            &self.target,
            self.database,
            &self.command,
            &self.target_args,
            delivered,
            &self.values,
            &mut |source_position,
                  target_position,
                  source_pattern,
                  target_pattern,
                  source,
                  target,
                  time| {
                records.push(
                    TimeCopyRecord::new_time(
                        time,
                        source_position,
                        target_position,
                        source_pattern,
                        target_pattern,
                        source,
                        target,
                    )?
                    .with_redis_get(redis_get),
                );
                Ok(())
            },
        )?;
        self.owner.record_time_copies(
            &self.case,
            records,
            crate::value_contract::time::ClockPair {
                source: self.source_completed,
                target: Some(completed),
            },
        )
    }
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
        let (logical, scalar) = if let Some(logical) = crate::json_value::parse(payload) {
            (logical, false)
        } else if redis
            .map(|policy| policy.field(value.key))
            .transpose()?
            .flatten()
            .is_none()
            && let Some(scalar) =
                crate::value_contract::redis_scalar::decode_automatic(payload, global, clocks)?
        {
            (scalar.logical, true)
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
            plan: if scalar {
                ReadPlan::Scalar { json: false }
            } else {
                ReadPlan::Json(Arc::new(CodecPlan::compile(&crate::policy::Codec::Json)?))
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
            plan: ReadPlan::Scalar { json: scalar.json },
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
    position: TimeCopyPosition<'_>,
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
        TimeCopyPosition<'_>,
        TimeCopyPosition<'_>,
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
                ReadPlan::Scalar { json: true } => crate::json_value::parse(payload)
                    .context("delivered Redis scalar JSON is invalid")?,
                ReadPlan::Scalar { json: false } => Value::String(
                    std::str::from_utf8(payload)
                        .context("delivered Redis scalar is not UTF-8")?
                        .into(),
                ),
            })
        };
        let source_position = TimeCopyPosition::Redis {
            host: &target.host,
            port: target.port,
            database,
            key: &value.key,
            container: value.container,
            hash_field: value.hash_field.as_deref(),
        };
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
) -> TimeCopyPosition<'a> {
    TimeCopyPosition::Redis {
        host,
        port,
        database,
        key: value.key,
        container: value.container,
        hash_field: value.hash_field,
    }
}

pub(super) fn redis_global_time_write_lookups(
    position: TimeCopyPosition<'_>,
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

impl RequestContracts {
    pub(in crate::replay) fn prepare_redis_time_read(
        &self,
        context: &RedisRequestContext<'_>,
        source_args: &[Vec<u8>],
        target_args: &[Vec<u8>],
        source: &[u8],
        completed: Option<DateTime<Utc>>,
    ) -> Result<Option<PreparedRedisTimeRead>> {
        if self.global_json().is_none() && self.redis_policy().is_none() {
            return Ok(None);
        }
        let clocks = self.contract_clocks(
            Some(context.case),
            context.recorded_at,
            context.actual_at,
            completed,
            None,
        );
        let mut values = if let Some(global) = self.global_json() {
            prepare_global_values(
                context.command,
                source_args,
                source,
                global,
                self.redis_policy(),
                clocks,
            )?
        } else {
            Vec::new()
        };
        if let Some(policy) = self.redis_policy() {
            values.extend(prepare_scalar_values(
                context.command,
                source_args,
                source,
                policy,
                &self
                    .global_json()
                    .map(|plan| plan.time.clone())
                    .unwrap_or_default(),
                clocks,
            )?);
        }
        ensure!(
            values.iter().map(|value| value.leaves.len()).sum::<usize>() <= MAX_LEAVES,
            "Redis pending time read exceeds its bounded capacity"
        );
        if values.is_empty() {
            return Ok(None);
        }
        ensure!(
            target_args.iter().map(Vec::len).sum::<usize>() <= MAX_IDENTITIES,
            "Redis read argument identities exceed their bound"
        );
        let clocks = self.contract_clocks(
            Some(context.case),
            context.recorded_at,
            context.actual_at,
            completed,
            None,
        );
        let witness = self.witnesses.as_ref().map(|_| {
            use crate::policy_evidence::*;
            let pair = |p: crate::value_contract::time::ClockPair| ClockPair {
                source: p.source,
                target: p.target,
            };
            WitnessMetadata {
                surface: Surface::DependencyResponse,
                source_role: SourceRole::DependencyResponse,
                target_role: TargetRole::DeliveredInput,
                source: SourceIdentity {
                    case_id: context.case.into(),
                    exchange_id: None,
                    connection_id: context.connection_id.map(|id| id.to_string()),
                    sequence: context.sequence,
                },
                resource: Some(crate::policy::Resource {
                    protocol: crate::policy::Protocol::Redis,
                    endpoint: crate::policy::Endpoint {
                        host: context.target.host.clone(),
                        port: context.target.port,
                    },
                    database: Some(crate::policy::Database::Index(context.database)),
                    username: context.username.map(str::to_owned),
                }),
                operation: context.command.into(),
                slot: Slot::Value,
                clocks: WitnessClocks {
                    case: pair(clocks.case),
                    dependency: pair(clocks.dependency),
                    delivery: pair(clocks.delivery),
                },
            }
        });
        Ok(Some(PreparedRedisTimeRead {
            owner: self.clone(),
            case: context.case.into(),
            target: context.target.clone(),
            database: context.database,
            source_completed: completed,
            command: context.command.into(),
            target_args: target_args.to_vec(),
            values,
            witness,
            observation: context.observation_id.unwrap_or_else(uuid::Uuid::new_v4),
        }))
    }

    pub(in crate::replay) fn record_redis_time_read_witness(
        &self,
        prepared: &PreparedRedisTimeRead,
        source: Option<&[u8]>,
        delivered: &[u8],
        at: DateTime<Utc>,
    ) -> Result<()> {
        if let Some(metadata) = &prepared.witness {
            let mut metadata = metadata.clone();
            metadata.clocks.delivery.target = Some(at);
            self.record_delivery_witness(
                &prepared.observation.to_string(),
                metadata,
                source.context("Redis temporal read witness requires immutable Source bytes")?,
                delivered,
            )?;
        }
        Ok(())
    }
}
