//! Temporal leaves become copy evidence only after the read reaches the wire.
use super::*;
use crate::policy::{CompiledRule, Slot, Surface};
use crate::value_codec::CodecPlan;
use crate::value_contract::{
    encoded,
    json::VerifiedTimeCopy,
    time_copies::{self, TimeCopyLookup, TimeCopyPosition, TimeCopyRecord, TimeCopyStore},
};
use sha2::{Digest, Sha256};

const MAX_LEAVES: usize = 4096;
const MAX_IDENTITIES: usize = 1024 * 1024;

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
    plan: Arc<CodecPlan>,
    leaves: Vec<Leaf>,
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
                records.push(TimeCopyRecord::new_time(
                    time,
                    source_position,
                    target_position,
                    source_pattern,
                    target_pattern,
                    source,
                    target,
                )?);
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

fn eligible(rule: &CompiledRule) -> bool {
    time_copies::schema_rule(&rule.rule.id)
        && rule.rule.surface == Surface::DependencyResponse
        && matches!(rule.rule.slot, Slot::RedisValue(_))
        && rule
            .rule
            .contract
            .values()
            .any(|field| field.unconditional().time().is_some())
}

fn selects(rule: &CompiledRule, value: &RedisFieldValue<'_>) -> bool {
    eligible(rule)
        && matches!(rule.rule.slot, Slot::RedisValue(container) if container == value.container)
        && rule
            .rule
            .selector
            .key
            .as_ref()
            .is_some_and(|key| key.matches(value.key))
        && rule.rule.selector.hash_field.as_ref().is_none_or(|field| {
            value.hash_field.is_some_and(|value| field.matches(value)) || value.hash_field.is_none()
        })
}

fn prepare_values(
    target: &TargetKey,
    database: i64,
    command: &str,
    source_args: &[Vec<u8>],
    source: &[u8],
    rules: &[&CompiledRule],
) -> Result<Vec<ReadValue>> {
    let rules = rules
        .iter()
        .copied()
        .filter(|rule| {
            rule.rule
                .selector
                .resource
                .as_ref()
                .is_some_and(|resource| {
                    resource.protocol == crate::policy::Protocol::Redis
                        && resource.endpoint.host.eq_ignore_ascii_case(&target.host)
                        && resource.endpoint.port == target.port
                        && resource
                            .database
                            .as_ref()
                            .is_none_or(|db| db.index() == Some(database))
                })
        })
        .collect::<Vec<_>>();
    if !rules.iter().any(|rule| eligible(rule)) {
        return Ok(vec![]);
    }
    if !response_identities(command, source_args)?
        .iter()
        .any(|value| rules.iter().any(|rule| selects(rule, value)))
    {
        return Ok(vec![]);
    }
    let values = redis_field_values(command, source_args, Some(source))?;
    let mut prepared = Vec::new();
    let mut leaf_count = 0usize;
    let mut identity_bytes = 0usize;
    for (ordinal, value) in values.iter().enumerate() {
        let Some(payload) = value.payload else {
            continue;
        };
        let selected = rules
            .iter()
            .copied()
            .filter(|rule| selects(rule, value))
            .collect::<Vec<_>>();
        if selected.is_empty() {
            continue;
        }
        let plan = encoded::prepared_codec(&selected)?;
        let decoded = plan.decode(payload)?;
        let mut leaves = Vec::new();
        let mut strategies =
            BTreeMap::<String, (Arc<str>, Arc<crate::policy::TimeContract>)>::new();
        for rule in selected {
            for leaf in time_copies::leaves(&decoded.logical, rule)? {
                let (pattern, time) = strategies
                    .entry(leaf.pattern.clone())
                    .or_insert_with(|| (Arc::from(leaf.pattern.as_str()), Arc::new(leaf.time)));
                leaves.push(Leaf {
                    pattern: Arc::clone(pattern),
                    pointer: leaf.pointer,
                    value: leaf.value,
                    time: Arc::clone(time),
                });
            }
        }
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
            plan,
            leaves,
        });
    }
    Ok(prepared)
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
            Some(value.plan.decode(payload)?)
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
                Some(decoded) => decoded.logical.pointer(&leaf.pointer),
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

/// Both adapters and offline evidence reconstruction use the same carrier proof.
/// The recorder receives only bounded scalar pairs, after one decode per value.
pub(crate) fn redis_delivered_time_copies(
    read: RedisTimeRead<'_>,
    rules: &[&CompiledRule],
    record: &mut CopyRecorder<'_>,
) -> Result<usize> {
    let target = TargetKey {
        host: read.host.into(),
        port: read.port,
    };
    let values = prepare_values(
        &target,
        read.database,
        read.command,
        read.source_args,
        read.source_response,
        rules,
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

pub(crate) fn redis_time_write_proofs(
    store: &TimeCopyStore,
    case: &str,
    source_position: TimeCopyPosition<'_>,
    target_position: TimeCopyPosition<'_>,
    source: &crate::value_codec::DecodedValue,
    rules: &[&CompiledRule],
) -> Result<Vec<VerifiedTimeCopy>> {
    if !store.has_case(case) {
        return Ok(vec![]);
    }
    let mut proofs = Vec::new();
    for rule in rules {
        for leaf in time_copies::leaves(&source.logical, rule)? {
            if let Some(proof) = store.proof_for_source_time(
                &leaf.time,
                case,
                source_position,
                target_position,
                &leaf.pattern,
                &leaf.pattern,
                &leaf.value,
                &rule.rule.id,
            ) {
                proofs.push(proof.at(&leaf.pointer, &leaf.pattern));
            }
        }
    }
    Ok(proofs)
}

pub(super) fn redis_time_write_lookups(
    source_position: TimeCopyPosition<'_>,
    target_position: TimeCopyPosition<'_>,
    source: &crate::value_codec::DecodedValue,
    rules: &[&CompiledRule],
) -> Result<Vec<TimeCopyLookup>> {
    let mut lookups = Vec::new();
    for rule in rules {
        for leaf in time_copies::leaves(&source.logical, rule)? {
            if let Some(lookup) = TimeCopyLookup::new_time(
                &leaf.time,
                source_position,
                target_position,
                &leaf.pattern,
                &leaf.pattern,
                &leaf.value,
                &rule.rule.id,
            ) {
                lookups.push(lookup.at(&leaf.pointer, &leaf.pattern));
            }
        }
    }
    Ok(lookups)
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
        let rules = self.scoped_compiled_redis(context, Surface::DependencyResponse);
        let values = prepare_values(
            context.target,
            context.database,
            context.command,
            source_args,
            source,
            &rules,
        )?;
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

    #[cfg(test)]
    pub(in crate::replay) fn commit_redis_time_read(
        &self,
        prepared: &PreparedRedisTimeRead,
        source: Option<&[u8]>,
        delivered: &[u8],
        at: DateTime<Utc>,
    ) -> Result<()> {
        prepared.publish(delivered, at)?;
        self.record_redis_time_read_witness(prepared, source, delivered, at)
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
