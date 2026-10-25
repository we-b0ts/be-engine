//! Rebuild read provenance from successful protected inputs, in Source order.
//! Target delivery clocks exclude reads that happened after a candidate write.
use std::borrow::Cow;

use super::*;
use crate::policy_evidence::{SourceRole, WitnessEntry, WitnessRef};
use crate::value_contract::time_copies::{TimeCopyPosition, TimeCopyRecord, TimeCopyStore};

pub(super) struct ReadEvidence<'a> {
    pub private: &'a Path,
    pub directory: &'a Path,
    pub report: &'a Value,
    pub case_started: Option<DateTime<Utc>>,
    pub responses: Vec<WitnessEntry<'a>>,
    pub requests: Vec<WitnessEntry<'a>>,
}

pub(super) fn identity(
    case: &str,
    event: &Value,
) -> Option<crate::policy_evidence::SourceIdentity> {
    if dependency::protocol(event) == Some(Protocol::Http) {
        return Some(crate::policy_evidence::SourceIdentity {
            case_id: case.into(),
            exchange_id: Some(event["id"].as_str()?.into()),
            connection_id: None,
            sequence: None,
        });
    }
    let sequence = if dependency::protocol(event) == Some(Protocol::Mysql) {
        event["query_sequence"].as_u64()?
    } else {
        event["sequence"].as_u64()?
    };
    Some(crate::policy_evidence::SourceIdentity {
        case_id: case.into(),
        exchange_id: None,
        connection_id: Some(event["connection_id"].as_str()?.into()),
        sequence: Some(sequence),
    })
}

fn observation(id: &str) -> &str {
    id.strip_suffix(":DependencyRequest:IndependentTargetObservation")
        .or_else(|| id.strip_suffix(":DependencyResponse:DeliveredInput"))
        .unwrap_or(id)
}

struct Requests<'a> {
    values: Vec<Cow<'a, WitnessRef>>,
    ids: BTreeMap<String, Vec<usize>>,
}

impl<'a> Requests<'a> {
    fn new(
        entries: Vec<WitnessEntry<'a>>,
        event: &Value,
        evidence: &ReadEvidence<'_>,
    ) -> Result<Self> {
        let mut out = Self {
            values: vec![],
            ids: BTreeMap::new(),
        };
        for entry in entries {
            let witness = entry.expand()?;
            if witness.metadata.target_role != TargetRole::IndependentTargetObservation {
                continue;
            }
            dependency::validate_metadata(&witness, event)?;
            crate::policy_evidence::verify_case_clock(&witness, evidence.report)?;
            let index = out.values.len();
            if let Some(id) = witness.target_observation_id.as_deref() {
                out.ids
                    .entry(observation(id).into())
                    .or_default()
                    .push(index);
            }
            out.values.push(witness);
        }
        Ok(out)
    }

    fn arguments(
        &self,
        response: &WitnessRef,
        source: &[u8],
        evidence: &ReadEvidence<'_>,
    ) -> Result<Option<Vec<Vec<u8>>>> {
        let indices = response
            .target_observation_id
            .as_deref()
            .and_then(|id| self.ids.get(observation(id)));
        let mut selected: Option<Vec<Vec<u8>>> = None;
        let source_hash = crate::policy_evidence::digest(source);
        for &index in indices.into_iter().flatten() {
            let witness = &self.values[index];
            if witness.source_sha256 != source_hash
                || witness.metadata.clocks.case != response.metadata.clocks.case
                || witness.metadata.clocks.dependency.target
                    != response.metadata.clocks.dependency.target
            {
                continue;
            }
            let (retained, target) =
                crate::policy_evidence::read(evidence.private, witness, evidence.directory)?;
            ensure!(
                retained == source,
                "temporal read request differs from immutable Source"
            );
            let Some(target) = target else {
                continue;
            };
            let args: Vec<Vec<u8>> = serde_json::from_slice(&target)?;
            if selected.as_ref().is_some_and(|previous| *previous != args) {
                return Ok(None);
            }
            selected = Some(args);
        }
        Ok(selected)
    }
}

pub(super) fn observe_global(
    store: &mut TimeCopyStore,
    case: &str,
    event: &Value,
    source: &[u8],
    policy: &CompiledPolicy,
    mut evidence: ReadEvidence<'_>,
) -> Result<()> {
    // The live hooks capture only successfully delivered, ordinary Case reads.
    // A protected payload does not grant snapshot or shared-inventory ownership.
    if event["replay_safe"] == false
        || !event["global_dependency_reason"].is_null()
        || !event["cache_snapshot_rule"].is_null()
        || event["cache_snapshot_hit"] == true
        || (!event["outcome"].is_null() && event["outcome"] != "response")
    {
        return Ok(());
    }
    ensure!(
        evidence.responses.len() + evidence.requests.len() <= 16384,
        "temporal read candidate inventory exceeds its bound"
    );
    let requests = Requests::new(std::mem::take(&mut evidence.requests), event, &evidence)?;
    let source_request = if dependency::protocol(event) == Some(Protocol::Redis) {
        Some(dependency::source_witness(
            Surface::DependencyRequest,
            event,
            evidence.directory,
        )?)
    } else {
        None
    };
    let source_hash = crate::policy_evidence::digest(source);
    for entry in std::mem::take(&mut evidence.responses) {
        let witness = entry.expand()?;
        if witness.metadata.source_role != SourceRole::DependencyResponse
            || witness.metadata.target_role != TargetRole::DeliveredInput
            || witness.source_sha256 != source_hash
        {
            continue;
        }
        dependency::validate_metadata(&witness, event)?;
        crate::policy_evidence::verify_case_clock(&witness, evidence.report)?;
        let completed = timestamp(&event["timestamp"]);
        let started = timestamp(&event["request_started_at"]).or_else(|| {
            completed
                .zip(event["duration_ms"].as_u64())
                .and_then(|(time, duration)| {
                    time.checked_sub_signed(chrono::TimeDelta::milliseconds(
                        i64::try_from(duration).ok()?,
                    ))
                })
        });
        ensure!(
            witness.metadata.clocks.case.source == evidence.case_started
                && witness
                    .metadata
                    .clocks
                    .dependency
                    .source
                    .is_none_or(|time| Some(time) == started)
                && witness
                    .metadata
                    .clocks
                    .delivery
                    .source
                    .is_none_or(|time| Some(time) == completed),
            "temporal read anchors differ from immutable Source"
        );
        let Some(delivered_at) = witness.metadata.clocks.delivery.target else {
            continue;
        };
        let (retained, target) =
            crate::policy_evidence::read(evidence.private, &witness, evidence.directory)?;
        ensure!(
            retained == source,
            "temporal read differs from immutable Source response"
        );
        let Some(target) = target else {
            continue;
        };
        let resource = witness
            .metadata
            .resource
            .as_ref()
            .context("temporal read lacks its observed resource")?;
        store.set_record_clocks(crate::value_contract::time::ClockPair {
            source: completed,
            target: Some(delivered_at),
        });
        let mut records = Vec::new();
        let mut record = |before: TimeCopyPosition<'_>,
                          after: TimeCopyPosition<'_>,
                          before_path: &str,
                          after_path: &str,
                          source: &Value,
                          target: &Value,
                          time: &crate::policy::TimeContract| {
            records.push(TimeCopyRecord::new_time(
                time,
                before,
                after,
                before_path,
                after_path,
                source,
                target,
            )?);
            Ok(())
        };
        let clocks = witness.metadata.clocks.comparison();
        match resource.protocol {
            Protocol::Mysql => {
                crate::replay::mysql_global_delivered_time_copies(
                    source,
                    &target,
                    policy,
                    resource,
                    event["database"].as_str(),
                    clocks,
                    &mut record,
                )?;
            }
            Protocol::Redis => {
                let Some(target_args) =
                    requests.arguments(&witness, source_request.as_ref().unwrap(), &evidence)?
                else {
                    continue;
                };
                let args = arguments(event)?;
                let read = crate::replay::RedisTimeRead {
                    host: &resource.endpoint.host,
                    port: resource.endpoint.port,
                    database: event["database"]
                        .as_i64()
                        .context("temporal Redis read lacks its actual database")?,
                    command: event["command"]
                        .as_str()
                        .context("temporal Redis read lacks its operation")?,
                    source_args: &args,
                    target_args: &target_args,
                    source_response: source,
                    delivered_response: &target,
                };
                if let Some(redis) = &policy.redis {
                    crate::replay::redis_delivered_scalar_time_copies(
                        read,
                        redis,
                        clocks,
                        &mut record,
                    )?;
                }
                if let Some(plan) = &policy.global_json {
                    crate::replay::redis_delivered_global_time_copies(
                        read,
                        plan,
                        clocks,
                        &mut record,
                    )?;
                }
            }
            _ => (),
        }
        store.record_batch(case, records)?;
    }
    Ok(())
}
