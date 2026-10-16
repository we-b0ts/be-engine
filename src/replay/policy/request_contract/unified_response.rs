//! Redis response-slot adapter. This validates a recorded input and writes a
//! derived delivery copy; it does not invent an independent Target response.
use super::*;
use crate::policy::{CompiledRule, Protocol, Surface};
use crate::value_contract::{delivery, json::AnchorClocks, time::ClockPair};

#[derive(Debug, Clone)]
pub(in crate::replay) struct PreparedRedisDelivery {
    original: Vec<u8>,
    payload: Value,
    rules: Vec<CompiledRule>,
    clocks: AnchorClocks,
    witness: Option<crate::policy_evidence::WitnessMetadata>,
}

impl PreparedRedisDelivery {
    pub(in crate::replay) fn render(&self, now: DateTime<Utc>) -> Result<Vec<u8>> {
        let mut clocks = self.clocks;
        clocks.delivery.target = Some(now);
        if self.rules.iter().all(|rule| rule.delivery_time.is_empty()) {
            return Ok(self.original.clone());
        }
        let rules = self.rules.iter().collect::<Vec<_>>();
        let payload = delivery::materialize(&self.payload, &rules, clocks)?;
        let body = serde_json::to_vec(&payload)?;
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
        duration_ms: u64,
        connection_id: uuid::Uuid,
        sequence: u64,
    ) -> Option<Result<PreparedRedisDelivery>> {
        let compiled = self.compiled_rules()?;
        let rules = compiled
            .rules
            .iter()
            .filter(|compiled| {
                let rule = &compiled.rule;
                rule.surface == Surface::DependencyResponse
                    && self.matches_compiled_case(compiled, Some(case))
                    && rule.selector.resource.as_ref().is_some_and(|resource| {
                        resource.protocol == Protocol::Redis
                            && resource.endpoint.host.eq_ignore_ascii_case(&target.host)
                            && resource.endpoint.port == target.port
                            && resource
                                .database
                                .as_ref()
                                .is_none_or(|selected| selected.index() == Some(database))
                            && resource
                                .username
                                .as_deref()
                                .is_none_or(|selected| Some(selected) == username)
                    })
                    && rule.selector.operation.as_deref() == Some(command)
                    && rule
                        .selector
                        .key
                        .as_ref()
                        .is_some_and(|key| args.first().is_some_and(|value| key.matches(value)))
            })
            .cloned()
            .collect::<Vec<_>>();
        if rules.is_empty() {
            return None;
        }
        Some((|| {
            ensure!(
                matches!(command, "GET" | "HGET"),
                "selected Redis response value slot is unsupported for this operation"
            );
            ensure!(
                rules.iter().all(|rule| rule.rule.codec.is_json()),
                "selected Redis response codec has no installed adapter"
            );
            let payload = decode_bulk(response)?;
            // Missing/null/error envelopes cannot satisfy a JSON value contract.
            for rule in &rules {
                for (pointer, contract) in &rule.rule.contract {
                    if !pointer.contains('*') {
                        let value = payload
                            .pointer(pointer)
                            .context("Source response selected field is missing")?;
                        match contract {
                            crate::policy::FieldContract::Unordered => ensure!(
                                value.is_array(),
                                "unordered Source response field requires an array"
                            ),
                            crate::policy::FieldContract::Time { .. } => {
                                let contract = contract.time().unwrap();
                                crate::value_contract::time::parse_timestamp(
                                    value,
                                    crate::value_contract::json::core_format(contract.format),
                                    contract.offset()?,
                                )?;
                            }
                            crate::policy::FieldContract::Duration { .. } => {
                                ensure!(value.is_number(), "Source duration requires a number")
                            }
                        }
                    }
                }
            }
            let started = observed.and_then(|time| {
                i64::try_from(duration_ms)
                    .ok()
                    .and_then(|ms| time.checked_sub_signed(chrono::Duration::milliseconds(ms)))
            });
            let clocks = self.contract_clocks(Some(case), started, None, observed, None);
            let original_clocks = AnchorClocks {
                case: ClockPair {
                    source: clocks.case.source,
                    target: clocks.case.source,
                },
                dependency: ClockPair {
                    source: clocks.dependency.source,
                    target: clocks.dependency.source,
                },
                delivery: ClockPair {
                    source: clocks.delivery.source,
                    target: clocks.delivery.source,
                },
            };
            let fields = rules
                .iter()
                .flat_map(|rule| {
                    rule.rule.contract.iter().map(move |(pointer, contract)| {
                        crate::value_contract::json::Field {
                            rule_id: &rule.rule.id,
                            pointer,
                            contract,
                        }
                    })
                })
                .collect::<Vec<_>>();
            let check =
                crate::value_contract::json::compare(&payload, &payload, &fields, original_clocks);
            ensure!(
                check.passed(),
                "Source response does not satisfy its declared contract: {:?}",
                check.differences
            );
            let witness = self.witnesses.as_ref().map(|_| {
                use crate::policy_evidence::*;
                WitnessMetadata {
                    surface: Surface::DependencyResponse,
                    source_role: SourceRole::RecordedDependencyResponse,
                    target_role: TargetRole::DerivedDelivery,
                    source: SourceIdentity {
                        case_id: case.into(),
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
                        case: crate::policy_evidence::ClockPair {
                            source: clocks.case.source,
                            target: clocks.case.target,
                        },
                        dependency: crate::policy_evidence::ClockPair {
                            source: clocks.dependency.source,
                            target: clocks.dependency.target,
                        },
                        delivery: crate::policy_evidence::ClockPair {
                            source: clocks.delivery.source,
                            target: None,
                        },
                    },
                }
            });
            Ok(PreparedRedisDelivery {
                original: response.into(),
                payload,
                rules,
                clocks,
                witness,
            })
        })())
    }

    pub(in crate::replay) fn commit_redis_delivery(
        &self,
        prepared: &PreparedRedisDelivery,
        delivered: &[u8],
    ) -> Result<()> {
        if let Some(metadata) = &prepared.witness {
            let mut metadata = metadata.clone();
            metadata.clocks.delivery.target = Some(Utc::now());
            self.record_value_witness(metadata, &prepared.original, Some(delivered))?;
        }
        self.commit(Decision {
            ids: prepared
                .rules
                .iter()
                .map(|rule| rule.rule.id.clone())
                .collect(),
            ..Default::default()
        });
        Ok(())
    }
}

fn decode_bulk(raw: &[u8]) -> Result<Value> {
    ensure!(
        raw.len() <= 1024 * 1024 && raw.first() == Some(&b'$'),
        "Redis response value requires a bounded bulk string"
    );
    let header = raw
        .windows(2)
        .position(|bytes| bytes == b"\r\n")
        .context("Redis response bulk header missing")?;
    let length = std::str::from_utf8(&raw[1..header])?
        .parse::<usize>()
        .context("Redis null/error is not a JSON value")?;
    let start = header + 2;
    let end = start
        .checked_add(length)
        .context("Redis bulk length overflow")?;
    ensure!(
        end.checked_add(2) == Some(raw.len()) && raw.get(end..) == Some(b"\r\n"),
        "Redis response must contain one complete bulk string"
    );
    crate::json_value::parse(&raw[start..end]).context("Redis response requires unique-member JSON")
}
