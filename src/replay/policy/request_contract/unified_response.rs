//! Recorded Redis storage values and explicit delivery copies with exact RESP remainder.
use super::*;
use crate::policy::Surface;
use crate::replay::contract_value::Delivery;
mod contextual;

#[derive(Debug, Clone)]
struct PreparedValue {
    range: std::ops::Range<usize>,
    header_len: usize,
    delivery: ValueDelivery,
}

#[derive(Debug, Clone)]
enum ValueDelivery {
    Json(Box<Delivery>),
    Scalar(Box<redis_fields::ScalarDelivery>),
}
impl ValueDelivery {
    fn validation(&self) -> &crate::value_contract::json::Comparison {
        match self {
            Self::Json(value) => value.validation(),
            Self::Scalar(value) => value.validation(),
        }
    }
    fn has_identities(&self) -> bool {
        match self {
            Self::Json(value) => value.has_identities(),
            Self::Scalar(value) => value.has_identities(),
        }
    }
    fn render(&self, now: DateTime<Utc>) -> Result<Vec<u8>> {
        match self {
            Self::Json(value) => value.render(now),
            Self::Scalar(value) => value.render(now),
        }
    }
    fn render_with_identities(
        &self,
        now: DateTime<Utc>,
        owner: &RequestContracts,
        case: &str,
    ) -> Result<(Vec<u8>, crate::value_contract::identities::IdentityDecision)> {
        match self {
            Self::Json(value) => value.render_with_identities(now, owner, case),
            Self::Scalar(value) => value.render_with_identities(now, owner, case),
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct PreparedRedisDelivery {
    owner: RequestContracts,
    case: String,
    observation_id: uuid::Uuid,
    original: Vec<u8>,
    values: Vec<PreparedValue>,
    witness: Option<crate::policy_evidence::WitnessMetadata>,
}

impl PreparedRedisDelivery {
    #[cfg(test)]
    pub(in crate::replay) fn render(&self, now: DateTime<Utc>) -> Result<Vec<u8>> {
        self.render_consistent(now, None)
    }

    pub(in crate::replay) fn render_consistent(
        &self,
        now: DateTime<Utc>,
        native: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut response = Vec::with_capacity(self.original.len());
        let mut previous = 0;
        let mut identities = None::<crate::value_contract::identities::IdentityDecision>;
        let mut contextual = contextual::Consistency::new(native);
        for value in &self.values {
            ensure!(
                value.range.start >= previous,
                "overlapping Redis delivery values"
            );
            response.extend_from_slice(&self.original[previous..value.range.start]);
            let body = if value.delivery.has_identities() {
                let (body, decision) =
                    value
                        .delivery
                        .render_with_identities(now, &self.owner, &self.case)?;
                if let Some(identities) = &mut identities {
                    identities.merge(decision)?;
                } else {
                    identities = Some(decision);
                }
                body
            } else {
                value.delivery.render(now)?
            };
            contextual.value(
                &self.original[previous..value.range.start],
                &body,
                &value.delivery,
            )?;
            if body.len() == value.range.len() - value.header_len - 2 {
                response.extend_from_slice(
                    &self.original[value.range.start..value.range.start + value.header_len],
                );
            } else {
                response.extend_from_slice(format!("${}\r\n", body.len()).as_bytes());
            }
            response.extend(body);
            response.extend_from_slice(b"\r\n");
            previous = value.range.end;
        }
        response.extend_from_slice(&self.original[previous..]);
        contextual.finish(&self.original[previous..])?;
        if let Some(identities) = identities {
            // Reserve the complete response atomically before any ID reaches
            // another Target connection. A failed wire write keeps this
            // conservative anchor until the case ends.
            self.owner.commit_identity(identities)?;
        }
        Ok(native.map_or(response, <[u8]>::to_vec))
    }
}

impl RequestContracts {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay) fn prepare_redis_delivery(
        &self,
        case: &str,
        source_case: &str,
        target: &TargetKey,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
        actual_args: &[Vec<u8>],
        response: &[u8],
        observed: Option<DateTime<Utc>>,
        actual_started: Option<DateTime<Utc>>,
        source_started: Option<DateTime<Utc>>,
        connection_id: uuid::Uuid,
        sequence: u64,
    ) -> Option<Result<PreparedRedisDelivery>> {
        self.compiled_rules()?;
        if self.global_json().is_none() && self.redis_policy().is_none() {
            return None;
        }
        let values = redis_field_values(command, args, Some(response)).ok()?;
        if values.iter().all(|value| {
            value.payload.is_none_or(|payload| {
                let scalar = self
                    .redis_policy()
                    .and_then(|policy| policy.field(value.key).ok().flatten())
                    .is_some()
                    && crate::value_contract::redis_scalar::decode(payload)
                        .is_ok_and(|value| value.is_some());
                !scalar
                    && (self.global_json().is_none() || crate::json_value::parse(payload).is_none())
            })
        }) {
            return None;
        }
        Some((|| {
            let mut clocks = self.contract_clocks(
                Some(source_case),
                source_started,
                actual_started,
                observed,
                None,
            );
            clocks.case.target = self.request_times(case).target;
            let target_values = redis_field_values(command, actual_args, Some(response))?;
            ensure!(
                values.len() == target_values.len(),
                "Redis read carrier count changed"
            );
            let context = RedisRequestContext {
                case,
                target,
                database,
                username,
                command,
                recorded_at: source_started,
                actual_at: actual_started,
                connection_id: Some(connection_id),
                sequence: Some(sequence),
                observation_id: None,
            };
            let mut prepared = Vec::new();
            for (value, target_value) in values.iter().zip(&target_values) {
                let Some(payload) = value.payload else {
                    continue;
                };
                let delivery =
                    if let Some(scalar) = self.scalar_delivery(value.key, payload, clocks)? {
                        ValueDelivery::Scalar(Box::new(scalar))
                    } else if let Some(global) = self.global_json()
                        && crate::json_value::parse(payload).is_some()
                    {
                        let copies =
                            self.redis_known_times(&context, value, target_value, global, clocks)?;
                        ValueDelivery::Json(Box::new(
                            Delivery::prepare_global(payload, global, clocks)?.with_copies(copies),
                        ))
                    } else {
                        continue;
                    };
                let range = value
                    .response
                    .clone()
                    .context("Redis delivery value position missing")?;
                prepared.push(PreparedValue {
                    header_len: range.len() - payload.len() - 2,
                    range,
                    delivery,
                });
            }
            let witness = self.witnesses.as_ref().map(|_| {
                use crate::policy_evidence::*;
                WitnessMetadata {
                    surface: Surface::DependencyResponse,
                    source_role: SourceRole::DependencyResponse,
                    target_role: TargetRole::DerivedDelivery,
                    source: SourceIdentity {
                        case_id: source_case.into(),
                        exchange_id: None,
                        connection_id: Some(connection_id.to_string()),
                        sequence: Some(sequence),
                    },
                    resource: Some(crate::policy::Resource {
                        protocol: crate::policy::Protocol::Redis,
                        endpoint: crate::policy::Endpoint {
                            host: target.host.clone(),
                            port: target.port,
                        },
                        database: Some(crate::policy::Database::Index(database)),
                        username: username.map(str::to_owned),
                    }),
                    operation: command.into(),
                    slot: crate::policy::Slot::Value,
                    clocks: WitnessClocks {
                        case: ClockPair {
                            source: clocks.case.source,
                            target: clocks.case.target,
                        },
                        dependency: ClockPair {
                            source: clocks.dependency.source,
                            target: clocks.dependency.target,
                        },
                        delivery: ClockPair {
                            source: clocks.delivery.source,
                            target: None,
                        },
                    },
                }
            });
            Ok(PreparedRedisDelivery {
                owner: self.clone(),
                case: case.into(),
                observation_id: uuid::Uuid::new_v4(),
                original: response.into(),
                values: prepared,
                witness,
            })
        })())
    }

    pub(in crate::replay) fn commit_redis_delivery(
        &self,
        prepared: &PreparedRedisDelivery,
        delivered: &[u8],
        rendered_at: DateTime<Utc>,
    ) -> Result<()> {
        if let Some(metadata) = &prepared.witness {
            let mut metadata = metadata.clone();
            metadata.clocks.delivery.target = Some(rendered_at);
            if metadata.source.case_id == prepared.case {
                self.record_delivery_witness(
                    &prepared.observation_id.to_string(),
                    metadata,
                    &prepared.original,
                    delivered,
                )?;
            } else if let Some(store) = &self.witnesses {
                // The finite sharing owner relates the two cases. The ordinary
                // witness graph must not invent a same-case Source association.
                let origin = self.anchor(&metadata.source.case_id)?;
                let target = self.anchor(&prepared.case)?;
                let mut target_metadata =
                    crate::policy_evidence::TargetMetadata::from_pair(&metadata);
                target_metadata.case_id = prepared.case.clone();
                metadata.target_role = crate::policy_evidence::TargetRole::Unavailable;
                store.record_observation(metadata, &origin.dir, &prepared.original, None, None)?;
                store.record_target(
                    &prepared.observation_id.to_string(),
                    target_metadata,
                    &target.dir,
                    delivered,
                )?;
            }
        }
        let mut decision = Decision::default();
        for value in &prepared.values {
            let comparison = value.delivery.validation();
            for id in &comparison.evaluated {
                if !decision.ids.contains(id) {
                    decision.ids.push(id.clone());
                }
            }
            for (id, count) in &comparison.time_validations {
                *decision
                    .unified_time_validations
                    .entry(id.clone())
                    .or_default() += count;
            }
        }
        self.commit(decision)
    }
}

pub(crate) fn redis_bulk_payload(raw: &[u8]) -> Result<Option<Vec<u8>>> {
    ensure!(
        raw.len() <= 1024 * 1024,
        "Redis response value exceeds 1 MiB"
    );
    // RESP3 null has no value, and must retain its own protocol representation.
    if raw == b"_\r\n" {
        return Ok(None);
    }
    let bytes = bytes::Bytes::copy_from_slice(raw);
    let (frame, consumed) = redis_protocol::resp2::decode::decode_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid Redis response: {e}"))?
        .context("incomplete Redis response")?;
    ensure!(
        consumed == bytes.len(),
        "Redis value requires one complete response frame"
    );
    use redis_protocol::resp2::types::BytesFrame;
    match frame {
        BytesFrame::BulkString(value) => Ok(Some(value.to_vec())),
        BytesFrame::Null | BytesFrame::Error(_) => Ok(None),
        _ => anyhow::bail!("selected Redis response does not expose a bulk value"),
    }
}
