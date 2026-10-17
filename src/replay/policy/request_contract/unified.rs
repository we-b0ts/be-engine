//! Redis value-slot adapter for the shared compiled contract evaluator.
//! This adapter never claims lanes, consumes exchanges, or changes auth/key/options.
use super::*;
use crate::policy::{CompiledPolicy, CompiledRule, Protocol, Surface};
use crate::policy_evidence::{
    AssociationOutcome, ClockPair as WitnessClockPair, ObservationRetention, SourceIdentity,
    SourceRole, TargetRole, WitnessClocks, WitnessMetadata, WitnessStore,
};
use crate::value_contract::{json, time::ClockPair};

pub(in crate::replay) struct RedisRequestContext<'a> {
    pub case: &'a str,
    pub target: &'a TargetKey,
    pub database: i64,
    pub username: Option<&'a str>,
    pub command: &'a str,
    pub recorded_at: Option<DateTime<Utc>>,
    pub actual_at: Option<DateTime<Utc>>,
    pub connection_id: Option<uuid::Uuid>,
    pub sequence: Option<u64>,
    pub observation_id: Option<uuid::Uuid>,
}

impl<'a> RedisRequestContext<'a> {
    #[cfg(test)]
    pub(super) fn without_exchange(
        case: &'a str,
        target: &'a TargetKey,
        database: i64,
        command: &'a str,
    ) -> Self {
        Self {
            case,
            target,
            database,
            username: None,
            command,
            recorded_at: None,
            actual_at: None,
            connection_id: None,
            sequence: None,
            observation_id: Some(uuid::Uuid::new_v4()),
        }
    }
}

pub(super) fn source_body(request: &Value) -> Option<Value> {
    if request["body"]
        .get("decode_error")
        .is_some_and(|value| !value.is_null())
    {
        return None;
    }
    let bytes = evidence::decode(&request["body"]).ok()?;
    crate::json_value::parse(&bytes)
}

impl RequestContracts {
    pub(in crate::replay) fn retains_value_witnesses(&self) -> bool {
        self.witnesses.is_some()
    }
    pub(in crate::replay::policy) fn configure_compiled(
        &mut self,
        compiled: Option<Arc<CompiledPolicy>>,
    ) -> Result<()> {
        self.mysql_selection = Arc::new(mysql_selection::MysqlSelection::new(compiled.as_deref())?);
        self.compiled = compiled;
        Ok(())
    }

    pub(in crate::replay) fn configure_witnesses(
        &mut self,
        store: WitnessStore,
        observe_sources: bool,
    ) -> Result<()> {
        self.witnesses = Some(store);
        if !observe_sources {
            return Ok(());
        }
        // Eager policy construction already validated Source applicability before
        // the protected store existed. Recount unavailable slots during this full
        // retention scan, rather than counting the same Source observation twice.
        self.state
            .lock()
            .expect("request contracts")
            .unavailable_value_slots
            .clear();
        let cases = self
            .state
            .lock()
            .expect("request contracts")
            .cases
            .iter()
            .map(|(id, anchor)| (id.clone(), anchor.dir.clone()))
            .collect::<Vec<_>>();
        for (id, dir) in cases {
            let path = dir.join("dependencies.jsonl");
            if path.is_file() {
                let bytes = std::fs::read(path)?;
                self.register_source_records(&id, &bytes)?;
                for line in bytes
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                {
                    let event: Value = serde_json::from_slice(line)?;
                    if !event["global_dependency_reason"].is_string() {
                        self.observe_unified_source(&id, &event)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub(in crate::replay) fn witness_manifest(
        &self,
    ) -> Option<crate::policy_evidence::WitnessManifest> {
        self.witnesses
            .as_ref()
            .and_then(|store| store.manifest().ok())
    }

    pub(in crate::replay) fn seal_witnesses(&self) -> Result<()> {
        if let Some(store) = &self.witnesses {
            store.sealed_manifest()?;
        }
        Ok(())
    }

    pub(in crate::replay) fn record_value_witness(
        &self,
        metadata: WitnessMetadata,
        source: &[u8],
        target: Option<&[u8]>,
    ) -> Result<()> {
        let Some(store) = &self.witnesses else {
            return Ok(());
        };
        let anchor = self.anchor(&metadata.source.case_id)?;
        store.record(metadata, &anchor.dir, source, target)?;
        Ok(())
    }

    pub(in crate::replay) fn record_delivery_witness(
        &self,
        id: &str,
        metadata: WitnessMetadata,
        source: &[u8],
        target: &[u8],
    ) -> Result<()> {
        let Some(store) = &self.witnesses else {
            return Ok(());
        };
        let anchor = self.anchor(&metadata.source.case_id)?;
        store.record_observation(metadata, &anchor.dir, source, Some(target), Some(id))?;
        Ok(())
    }

    pub(in crate::replay) fn record_target_observation(
        &self,
        id: &str,
        metadata: crate::policy_evidence::TargetMetadata,
        payload: &[u8],
    ) -> Result<ObservationRetention> {
        let Some(store) = &self.witnesses else {
            return Ok(ObservationRetention::Retained);
        };
        let anchor = self.anchor(&metadata.case_id)?;
        store.record_target(id, metadata, &anchor.dir, payload)
    }

    pub(in crate::replay) fn record_independent_request(
        &self,
        id: &str,
        case: &str,
        resource: Option<crate::policy::Resource>,
        operation: &str,
        observed: DateTime<Utc>,
        payload: &[u8],
    ) -> Result<ObservationRetention> {
        let clocks = self.contract_clocks(Some(case), None, Some(observed), None, None);
        self.record_target_observation(
            id,
            crate::policy_evidence::TargetMetadata {
                case_id: case.into(),
                surface: Surface::DependencyRequest,
                role: TargetRole::IndependentTargetObservation,
                resource,
                operation: operation.into(),
                clocks: WitnessClocks {
                    case: WitnessClockPair {
                        source: None,
                        target: clocks.case.target,
                    },
                    dependency: WitnessClockPair {
                        source: None,
                        target: clocks.dependency.target,
                    },
                    delivery: WitnessClockPair::default(),
                },
            },
            payload,
        )
    }

    pub(in crate::replay) fn associate_value_witness(
        &self,
        metadata: &WitnessMetadata,
        target_id: &str,
        source: Option<&[u8]>,
    ) -> Result<AssociationOutcome> {
        let Some(store) = &self.witnesses else {
            return Ok(AssociationOutcome::Retained);
        };
        let anchor = self.anchor(&metadata.source.case_id)?;
        store.associate(metadata, target_id, &anchor.dir, source)
    }

    pub(in crate::replay) fn compiled_rules(&self) -> Option<&Arc<CompiledPolicy>> {
        self.compiled.as_ref()
    }

    pub(in crate::replay) fn matches_compiled_case(
        &self,
        rule: &CompiledRule,
        case: Option<&str>,
    ) -> bool {
        let Some(case) = case else {
            return false;
        };
        let Ok(anchor) = self.anchor(case) else {
            return false;
        };
        rule.rule.selector.matches_api(&anchor.method, &anchor.path)
            && rule.rule.when.as_ref().is_none_or(|condition| {
                anchor
                    .source_body
                    .as_ref()
                    .is_some_and(|body| condition.matches_body(body))
            })
    }

    /// Native domains select immutable Source scope before any value rewriting.
    /// A native rule never borrows a Target body or an unknown rule identity.
    pub(in crate::replay) fn native_rule_scope_matches(
        &self,
        id: &str,
        case: Option<&str>,
        protocol: crate::policy::Protocol,
        target: &TargetKey,
        database: Option<&crate::policy::Database>,
        username: Option<&str>,
    ) -> bool {
        let Some(compiled) = self.compiled.as_ref() else {
            return true;
        };
        let Some(rule) = compiled.native.iter().find(|rule| rule.rule.id == id) else {
            return false;
        };
        let Some(anchor) = case.and_then(|case| self.anchor(case).ok()) else {
            return false;
        };
        let guard = super::super::native_projection::NativeScopeGuard::from_rule(&rule.rule);
        guard.matches_case(&anchor.method, &anchor.path, anchor.source_body.as_ref())
            && guard.matches_capture_resource(protocol, target, database, username)
    }

    pub(in crate::replay) fn contract_clocks(
        &self,
        case: Option<&str>,
        source_dependency: Option<DateTime<Utc>>,
        target_dependency: Option<DateTime<Utc>>,
        source_delivery: Option<DateTime<Utc>>,
        target_delivery: Option<DateTime<Utc>>,
    ) -> json::AnchorClocks {
        let case = case.and_then(|id| self.anchor(id).ok());
        json::AnchorClocks {
            case: ClockPair {
                source: case.as_ref().and_then(|anchor| anchor.recorded),
                target: case.and_then(|anchor| anchor.actual),
            },
            dependency: ClockPair {
                source: source_dependency,
                target: target_dependency,
            },
            delivery: ClockPair {
                source: source_delivery,
                target: target_delivery,
            },
        }
    }

    pub(in crate::replay) fn preview_redis_context(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        self.preview_unified_redis(context, source, actual)
            .or_else(|| self.preview_redis_legacy(context, source, actual))
    }

    pub(super) fn preview_unified_redis(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        // Matchers retain the original independent Target before normalization.
        // Re-evaluating comparison copies must never create another observation.
        let rules = self.unified_selected(
            context,
            source.first()?.as_slice(),
            Surface::DependencyRequest,
            source.get(1).map(Vec::as_slice),
        );
        if rules.is_empty() {
            return None;
        }
        Some((|| {
            let index = value_index(context.command, source.len())
                .context("command does not expose a supported Redis JSON value slot")?;
            ensure!(source.len() == actual.len(), "Redis argument count changed");
            ensure!(
                source
                    .iter()
                    .zip(actual)
                    .enumerate()
                    .all(|(i, (source, actual))| i == index || source == actual),
                "Redis key or unselected options/arguments changed"
            );
            let anchor = self.anchor(context.case)?;
            let clocks = json::AnchorClocks {
                case: ClockPair {
                    source: anchor.recorded,
                    target: anchor.actual,
                },
                dependency: ClockPair {
                    source: context.recorded_at,
                    target: context.actual_at,
                },
                ..Default::default()
            };
            let comparison = crate::value_contract::encoded::compare(
                &source[index],
                &actual[index],
                &rules,
                clocks,
            )?;
            ensure!(
                comparison.passed(),
                "Redis value contract failed: {}",
                serde_json::to_string(&comparison.differences)?
            );
            Ok(Decision {
                ids: comparison.evaluated.into_iter().collect(),
                unified_time_validations: comparison.time_validations,
                ..Default::default()
            })
        })())
    }

    pub(super) fn unified_selected(
        &self,
        context: &RedisRequestContext<'_>,
        key: &[u8],
        surface: Surface,
        hash_field: Option<&[u8]>,
    ) -> Vec<&CompiledRule> {
        let Some(policy) = &self.compiled else {
            return vec![];
        };
        let Ok(anchor) = self.anchor(context.case) else {
            return vec![];
        };
        policy
            .rules
            .iter()
            .filter(|compiled| {
                let rule = &compiled.rule;
                let Some(resource) = &rule.selector.resource else {
                    return false;
                };
                rule.surface == surface
                    && resource.protocol == Protocol::Redis
                    && resource
                        .endpoint
                        .host
                        .eq_ignore_ascii_case(&context.target.host)
                    && resource.endpoint.port == context.target.port
                    && resource
                        .database
                        .as_ref()
                        .is_none_or(|database| database.index() == Some(context.database))
                    && resource
                        .username
                        .as_ref()
                        .is_none_or(|username| Some(username.as_str()) == context.username)
                    && rule.selector.operation.as_deref() == Some(context.command)
                    && rule
                        .selector
                        .hash_field
                        .as_ref()
                        .is_none_or(|field| hash_field.is_some_and(|value| field.matches(value)))
                    && rule
                        .selector
                        .key
                        .as_ref()
                        .is_some_and(|selector| selector.matches(key))
                    && rule.selector.matches_api(&anchor.method, &anchor.path)
                    && rule.when.as_ref().is_none_or(|condition| {
                        anchor
                            .source_body
                            .as_ref()
                            .is_some_and(|body| condition.matches_body(body))
                    })
            })
            .collect()
    }

    pub(super) fn observe_unified_source(&self, case: &str, event: &Value) -> Result<()> {
        self.observe_unified_memcached_source(case, event)?;
        self.observe_unified_http_source(case, event)?;
        self.observe_unified_mysql_source(case, event)?;
        if self.compiled.is_none()
            || event["event_type"] != "redis_exchange"
            || event["replay_safe"] != true
        {
            return Ok(());
        }
        let Some(args) = event["args"].as_array() else {
            return Ok(());
        };
        let Some(first) = args.first() else {
            return Ok(());
        };
        let source = args
            .iter()
            .map(evidence::decode)
            .collect::<Result<Vec<_>>>()?;
        let key = evidence::decode(first)?;
        let target = TargetKey {
            host: event["target_host"].as_str().unwrap_or_default().into(),
            port: event["target_port"].as_u64().unwrap_or_default() as u16,
        };
        let context = RedisRequestContext {
            case,
            target: &target,
            database: event["database"].as_i64().unwrap_or_default(),
            username: event["username"].as_str(),
            command: event["command"].as_str().unwrap_or_default(),
            actual_at: None,
            observation_id: None,
            recorded_at: event["request_started_at"]
                .as_str()
                .and_then(|value| value.parse().ok())
                .or_else(|| {
                    event["timestamp"]
                        .as_str()
                        .and_then(|value| value.parse::<DateTime<Utc>>().ok())
                        .zip(event["duration_ms"].as_u64())
                        .and_then(|(completed, duration)| {
                            i64::try_from(duration).ok().and_then(|duration| {
                                completed
                                    .checked_sub_signed(chrono::TimeDelta::milliseconds(duration))
                            })
                        })
                }),
            connection_id: event["connection_id"]
                .as_str()
                .and_then(|value| value.parse().ok()),
            sequence: event["sequence"].as_u64(),
        };
        // Immutable inventory includes sequence commands and lock lifecycle
        // traffic, not just commands with a generic encoded value slot.
        self.record_unified_request(&context, &source, None);
        if matches!(context.command, "GET" | "HGET")
            && event["outcome"]
                .as_str()
                .is_none_or(|outcome| outcome == "response")
            && event["response_kind"] == "bulk_string"
        {
            let response = evidence::decode(&event["response"])?;
            if complete_bulk(&response) {
                self.record_unified_response_source(
                    &context,
                    &response,
                    event["timestamp"]
                        .as_str()
                        .and_then(|value| value.parse().ok()),
                );
            }
        }
        let mut ids = BTreeSet::new();
        for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
            let selected =
                self.unified_selected(&context, &key, surface, source.get(1).map(Vec::as_slice));
            if selected.is_empty() {
                continue;
            }
            let payload = if surface == Surface::DependencyResponse {
                let ordinary = event["outcome"]
                    .as_str()
                    .is_none_or(|outcome| outcome == "response");
                if ordinary {
                    super::unified_response::redis_bulk_payload(&evidence::decode(
                        &event["response"],
                    )?)?
                } else {
                    None
                }
            } else {
                value_index(context.command, source.len())
                    .and_then(|index| source.get(index).cloned())
            };
            let Some(payload) = payload else {
                self.observe_value_slot_unavailable(
                    selected.iter().map(|rule| rule.rule.id.clone()),
                );
                continue;
            };
            let clocks = self.contract_clocks(
                Some(case),
                context.recorded_at,
                None,
                event["timestamp"]
                    .as_str()
                    .and_then(|value| value.parse().ok()),
                None,
            );
            let validation =
                crate::replay::contract_value::Delivery::prepare(&payload, &selected, clocks)?;
            ids.extend(validation.validation().evaluated.iter().cloned());
        }
        self.state
            .lock()
            .expect("request contracts")
            .applicable
            .extend(ids);
        Ok(())
    }

    pub(in crate::replay) fn record_unified_request(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        target: Option<&[Vec<u8>]>,
    ) {
        let Some(store) = &self.witnesses else {
            return;
        };
        let Ok(anchor) = self.anchor(context.case) else {
            return;
        };
        let metadata = WitnessMetadata {
            surface: Surface::DependencyRequest,
            source_role: SourceRole::DependencyRequest,
            target_role: if target.is_some() {
                TargetRole::IndependentTargetObservation
            } else {
                TargetRole::Unavailable
            },
            source: SourceIdentity {
                exchange_id: None,
                case_id: context.case.into(),
                connection_id: context.connection_id.map(|value| value.to_string()),
                sequence: context.sequence,
            },
            resource: Some(crate::policy::Resource {
                protocol: Protocol::Redis,
                endpoint: crate::policy::Endpoint {
                    host: context.target.host.clone(),
                    port: context.target.port,
                },
                database: Some(crate::policy::Database::Index(context.database)),
                username: context.username.map(str::to_owned),
            }),
            operation: context.command.into(),
            slot: crate::policy::Slot::Value,
            clocks: WitnessClocks {
                case: WitnessClockPair {
                    source: anchor.recorded,
                    target: anchor.actual,
                },
                dependency: WitnessClockPair {
                    source: context.recorded_at,
                    target: context.actual_at,
                },
                ..Default::default()
            },
        };
        let result = (|| -> Result<()> {
            if target.is_some() {
                let Some(id) = context.observation_id else {
                    return Ok(());
                };
                let id = id.to_string();
                if store.associate(&metadata, &id, &anchor.dir, None)?
                    == AssociationOutcome::SourceRequired
                {
                    let source = serde_json::to_vec(source)?;
                    store.associate(&metadata, &id, &anchor.dir, Some(&source))?;
                }
            } else {
                store.record(metadata, &anchor.dir, &serde_json::to_vec(source)?, None)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            tracing::warn!(%error, "unified request witness could not be persisted; evidence coverage is incomplete");
        }
    }

    pub(in crate::replay) fn record_redis_target(
        &self,
        context: &RedisRequestContext<'_>,
        args: &[Vec<u8>],
    ) -> Result<ObservationRetention> {
        if self.compiled.is_none() || self.witnesses.is_none() {
            return Ok(ObservationRetention::Retained);
        }
        let id = context
            .observation_id
            .context("Redis Target observation identity is missing")?;
        let observed = context
            .actual_at
            .context("Redis Target observation clock is missing")?;
        self.record_independent_request(
            &id.to_string(),
            context.case,
            Some(crate::policy::Resource {
                protocol: Protocol::Redis,
                endpoint: crate::policy::Endpoint {
                    host: context.target.host.clone(),
                    port: context.target.port,
                },
                database: Some(crate::policy::Database::Index(context.database)),
                username: context.username.map(str::to_owned),
            }),
            context.command,
            observed,
            &serde_json::to_vec(args)?,
        )
    }

    fn record_unified_response_source(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[u8],
        delivered: Option<DateTime<Utc>>,
    ) {
        let Some(store) = &self.witnesses else {
            return;
        };
        let Ok(anchor) = self.anchor(context.case) else {
            return;
        };
        let metadata = WitnessMetadata {
            surface: Surface::DependencyResponse,
            source_role: SourceRole::DependencyResponse,
            target_role: TargetRole::Unavailable,
            source: SourceIdentity {
                exchange_id: None,
                case_id: context.case.into(),
                connection_id: context.connection_id.map(|value| value.to_string()),
                sequence: context.sequence,
            },
            resource: Some(crate::policy::Resource {
                protocol: Protocol::Redis,
                endpoint: crate::policy::Endpoint {
                    host: context.target.host.clone(),
                    port: context.target.port,
                },
                database: Some(crate::policy::Database::Index(context.database)),
                username: context.username.map(str::to_owned),
            }),
            operation: context.command.into(),
            slot: crate::policy::Slot::Value,
            clocks: WitnessClocks {
                case: WitnessClockPair {
                    source: anchor.recorded,
                    target: None,
                },
                dependency: WitnessClockPair {
                    source: context.recorded_at,
                    target: context.actual_at,
                },
                delivery: WitnessClockPair {
                    source: delivered,
                    target: None,
                },
            },
        };
        if let Err(error) = store.record(metadata, &anchor.dir, source, None) {
            tracing::warn!(%error, "recorded Redis response witness could not be persisted; coverage is incomplete");
        }
    }

    pub(super) fn unified_reports(
        &self,
        state: &State,
    ) -> Vec<super::super::report::DependencyRuleReport> {
        self.compiled
            .iter()
            .flat_map(|policy| &policy.rules)
            .filter_map(|compiled| {
                let rule = &compiled.rule;
                if rule.surface == Surface::ApiResponse {
                    return None;
                }
                let protocol = match rule.selector.resource.as_ref()?.protocol {
                    Protocol::Redis => DependencyProtocol::Redis,
                    Protocol::Http => DependencyProtocol::Http,
                    Protocol::Memcached => DependencyProtocol::Memcached,
                    Protocol::Mysql => DependencyProtocol::Mysql,
                };
                let matches = state.usage.get(&rule.id).copied().unwrap_or_default();
                Some(super::super::report::DependencyRuleReport {
                    id: rule.id.clone(),
                    protocol,
                    kind: Some(if rule.surface == Surface::DependencyResponse {
                        "source_to_delivery"
                    } else {
                        "dependency_request"
                    }),
                    applicable: state.applicable.contains(&rule.id),
                    matches,
                    binds: 0,
                    references: 0,
                    validations: matches,
                    time_validations: state
                        .time_validations
                        .get(&rule.id)
                        .copied()
                        .unwrap_or_default(),
                })
            })
            .collect()
    }
}

fn complete_bulk(raw: &[u8]) -> bool {
    if raw.first() != Some(&b'$') {
        return false;
    }
    let Some(header) = raw.windows(2).position(|bytes| bytes == b"\r\n") else {
        return false;
    };
    let Some(length) = std::str::from_utf8(&raw[1..header])
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return false;
    };
    let Some(end) = (header + 2).checked_add(length) else {
        return false;
    };
    end.checked_add(2) == Some(raw.len()) && raw.get(end..) == Some(b"\r\n")
}

pub(super) fn value_index(command: &str, length: usize) -> Option<usize> {
    match (command, length) {
        ("SET", 2..) | ("PUBLISH", 2) => Some(1),
        ("SETEX" | "PSETEX", 3) => Some(2),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
