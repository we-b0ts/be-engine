//! Recorded Redis storage values and explicit delivery copies with exact RESP remainder.
use super::*;
use crate::policy::{Slot, Surface};
use crate::replay::contract_value::Delivery;

#[derive(Debug, Clone)]
struct PreparedValue {
    range: std::ops::Range<usize>,
    header_len: usize,
    delivery: Delivery,
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
    pub(in crate::replay) fn render(&self, now: DateTime<Utc>) -> Result<Vec<u8>> {
        let mut response = Vec::with_capacity(self.original.len());
        let mut previous = 0;
        let mut identities = None::<crate::value_contract::identities::IdentityDecision>;
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
        if let Some(identities) = identities {
            // Reserve the complete response atomically before any ID reaches
            // another Target connection. A failed wire write keeps this
            // conservative anchor until the case ends.
            self.owner.commit_identity(identities)?;
        }
        Ok(response)
    }
}

impl RequestContracts {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay) fn prepare_redis_delivery(
        &self,
        case: &str,
        target: &TargetKey,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
        response: &[u8],
        observed: Option<DateTime<Utc>>,
        actual_started: Option<DateTime<Utc>>,
        source_started: Option<DateTime<Utc>>,
        connection_id: uuid::Uuid,
        sequence: u64,
    ) -> Option<Result<PreparedRedisDelivery>> {
        self.compiled_rules()?;
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
        let scoped = self.scoped_compiled_redis(&context, Surface::DependencyResponse);
        if scoped.is_empty() {
            return None;
        }
        let identities = redis_fields::response_identities(command, args).ok()?;
        if identities.iter().all(|value| {
            Self::filter_redis_value_rules(&scoped, &context, value)
                .iter()
                .all(|rule| {
                    matches!(rule.rule.slot, Slot::RedisValue(_))
                        && rule.delivery_time.is_empty()
                        && !crate::value_contract::identities::rules_have_identity(&[rule])
                })
        }) {
            return None;
        }
        let values = match redis_field_values(command, args, Some(response)) {
            Ok(values) => values,
            Err(error) => return Some(Err(error)),
        };
        let selected = values
            .iter()
            .filter_map(|value| {
                let payload = value.payload.as_ref()?;
                let rules = Self::filter_redis_value_rules(&scoped, &context, value);
                let rules = rules
                    .into_iter()
                    .filter(|rule| {
                        !matches!(rule.rule.slot, Slot::RedisValue(_))
                            || !rule.delivery_time.is_empty()
                            || crate::value_contract::identities::rules_have_identity(&[rule])
                    })
                    .collect::<Vec<_>>();
                (!rules.is_empty()).then_some((value, payload, rules))
            })
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return None;
        }
        Some((|| {
            let clocks =
                self.contract_clocks(Some(case), source_started, actual_started, observed, None);
            let mut prepared = Vec::new();
            for (value, payload, rules) in &selected {
                let range = value
                    .response
                    .clone()
                    .context("Redis delivery value position missing")?;
                prepared.push(PreparedValue {
                    header_len: range.len() - payload.len() - 2,
                    range,
                    delivery: Delivery::prepare(payload, rules, clocks)?,
                });
            }
            let witness = self.witnesses.as_ref().map(|_| {
                use crate::policy_evidence::*;
                WitnessMetadata {
                    surface: Surface::DependencyResponse,
                    source_role: SourceRole::DependencyResponse,
                    target_role: TargetRole::DerivedDelivery,
                    source: SourceIdentity {
                        case_id: case.into(),
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
                    slot: selected[0].2[0].rule.slot.clone(),
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
            self.record_delivery_witness(
                &prepared.observation_id.to_string(),
                metadata,
                &prepared.original,
                delivered,
            )?;
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
