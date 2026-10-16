//! Recorded Redis input validation and explicit JSON/PB delivery copies.
use super::*;
use crate::policy::{Protocol, Surface};
use crate::replay::contract_value::Delivery;

#[derive(Debug, Clone)]
pub(in crate::replay) struct PreparedRedisDelivery {
    original: Vec<u8>,
    value: Delivery,
    witness: Option<crate::policy_evidence::WitnessMetadata>,
}

impl PreparedRedisDelivery {
    pub(in crate::replay) fn render(&self, now: DateTime<Utc>) -> Result<Vec<u8>> {
        let body = self.value.render(now)?;
        let mut response = format!("${}\r\n", body.len()).into_bytes();
        response.extend(body);
        response.extend_from_slice(b"\r\n");
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
        let compiled = self.compiled_rules()?;
        let rules =
            compiled
                .rules
                .iter()
                .filter(|compiled| {
                    let rule = &compiled.rule;
                    rule.surface == Surface::DependencyResponse
                        && self.matches_compiled_case(compiled, Some(case))
                        && rule.selector.resource.as_ref().is_some_and(|r| {
                            r.protocol == Protocol::Redis
                                && r.endpoint.host.eq_ignore_ascii_case(&target.host)
                                && r.endpoint.port == target.port
                                && r.database
                                    .as_ref()
                                    .is_none_or(|d| d.index() == Some(database))
                                && r.username.as_deref().is_none_or(|u| Some(u) == username)
                        })
                        && rule.selector.operation.as_deref() == Some(command)
                        && rule.selector.hash_field.as_ref().is_none_or(|field| {
                            args.get(1).is_some_and(|value| field.matches(value))
                        })
                        && rule
                            .selector
                            .key
                            .as_ref()
                            .is_some_and(|key| args.first().is_some_and(|bytes| key.matches(bytes)))
                })
                .collect::<Vec<_>>();
        if rules.is_empty() {
            return None;
        }
        let payload = match redis_bulk_payload(response) {
            Ok(Some(value)) => value,
            Ok(None) => return None,
            Err(error) => return Some(Err(error)),
        };
        Some((|| {
            ensure!(
                matches!(command, "GET" | "HGET"),
                "unsupported Redis response value operation"
            );
            let clocks =
                self.contract_clocks(Some(case), source_started, actual_started, observed, None);
            let value = Delivery::prepare(&payload, &rules, clocks)?;
            let witness = self.witnesses.as_ref().map(|_| {
                use crate::policy_evidence::*;
                WitnessMetadata {
                    surface: Surface::DependencyResponse,
                    source_role: SourceRole::RecordedDependencyResponse,
                    target_role: TargetRole::DerivedDelivery,
                    source: SourceIdentity {
                        case_id: case.into(),
                        exchange_id: None,
                        connection_id: Some(connection_id.to_string()),
                        sequence: Some(sequence),
                    },
                    resource: Some(crate::policy::Resource {
                        protocol: Protocol::Redis,
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
                original: response.into(),
                value,
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
            self.record_value_witness(metadata, &prepared.original, Some(delivered))?;
        }
        self.commit(Decision::from_value_comparison(
            prepared.value.validation().clone(),
        ));
        Ok(())
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
