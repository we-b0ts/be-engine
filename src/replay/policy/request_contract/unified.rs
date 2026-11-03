//! Redis value-slot adapter for the shared compiled contract evaluator.
//! This adapter never claims lanes, consumes exchanges, or changes auth/key/options.
use super::*;
use crate::policy::{CompiledPolicy, Protocol, Surface};
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
    pub(in crate::replay) fn configure_compiled(
        &mut self,
        compiled: Option<Arc<CompiledPolicy>>,
    ) -> Result<()> {
        if let Some(global) = compiled
            .as_ref()
            .and_then(|policy| policy.global_json.as_ref())
            && global.signatures.needs_prepare()
        {
            let root = match self
                .input_origin
                .as_ref()
                .context("JWT runtime input origin unavailable")?
            {
                derived_inputs::InputOrigin::Root(root) => root.clone(),
                derived_inputs::InputOrigin::Policy(policy) => {
                    crate::config::resolve_unified_policy_root(policy)?
                }
            };
            global.signatures.prepare(&root)?;
        }
        self.native_dispatch = Arc::new(
            compiled
                .as_deref()
                .map(rule_dispatch::NativeDispatch::prepare)
                .transpose()?
                .unwrap_or_default(),
        );
        self.rule_catalogue = Arc::new(
            compiled
                .as_deref()
                .map(case_plan::RuleCatalogue::new)
                .unwrap_or_default(),
        );
        self.compiled = compiled;
        Ok(())
    }

    pub(in crate::replay) fn configure_witnesses(
        &mut self,
        store: WitnessStore,
        observe_sources: bool,
    ) -> Result<()> {
        if tokio::runtime::Handle::try_current().is_ok() {
            self.hypothesis_journal = Some(store.hypothesis_journal()?);
        }
        self.witnesses = Some(store);
        if !observe_sources {
            return Ok(());
        }
        let cases = self
            .state
            .lock()
            .expect("request contracts")
            .cases
            .iter()
            .map(|(id, anchor)| (id.clone(), anchor.dependencies_path.clone()))
            .collect::<Vec<_>>();
        for (id, path) in cases {
            if crate::dependency_index::scoped::exists(&path) {
                let bytes = crate::dependency_index::scoped::read_bytes(&path)?;
                self.register_source_records(&id, &bytes)?;
                for line in bytes
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                {
                    let event: Value = serde_json::from_slice(line)?;
                    if crate::dependency::observation::is_case_event(&event) {
                        self.observe_plan_fact(&id, &event);
                        self.observe_unified_source(&id, &event)?;
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::replay) fn witness_manifest(
        &self,
    ) -> Option<crate::policy_evidence::WitnessManifest> {
        self.witnesses
            .as_ref()
            .and_then(|store| store.manifest().ok())
    }

    #[cfg(test)]
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
                run_owner: None,
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
        if let Some(host) = &rule.rule.selector.http_host
            && (protocol != Protocol::Http
                || crate::replay::normalize_host(host)
                    != crate::replay::normalize_host(&target.host))
        {
            return false;
        }
        if rule.rule.selector.resource.is_none()
            && matches!(
                rule.rule.effect,
                crate::policy::NativeEffect::FiniteSharing(
                    crate::policy::native::FiniteSharingEffect::Http
                )
            )
        {
            return protocol == Protocol::Http
                && guard.matches_case(&anchor.method, &anchor.path, anchor.source_body.as_ref());
        }
        if rule.rule.selector.resource.is_none()
            && (matches!(
                rule.rule.effect,
                crate::policy::NativeEffect::RedisAppendStream
                    | crate::policy::NativeEffect::RedisExpiryRefresh(_)
                    | crate::policy::NativeEffect::RedisActivityRefresh(_)
                    | crate::policy::NativeEffect::RedisReadCommutation(_)
                    | crate::policy::NativeEffect::RedisReadObservation(_)
                    | crate::policy::NativeEffect::RedisSequence(_)
                    | crate::policy::NativeEffect::FiniteSharing(
                        crate::policy::native::FiniteSharingEffect::Redis { .. }
                    )
            ) || crate::policy::native::is_key_only_read_back(&rule.rule))
        {
            return protocol == Protocol::Redis
                && database
                    .and_then(crate::policy::Database::index)
                    .is_some_and(|observed| observed >= 0)
                && guard.matches_case(&anchor.method, &anchor.path, anchor.source_body.as_ref());
        }
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
        let case = case.and_then(|id| {
            self.state
                .lock()
                .expect("request contracts")
                .cases
                .get(id)
                .map(|anchor| (anchor.recorded, anchor.actual))
        });
        json::AnchorClocks::for_request(
            ClockPair {
                source: case.and_then(|(recorded, _)| recorded),
                target: case.and_then(|(_, actual)| actual),
            },
            ClockPair {
                source: source_dependency,
                target: target_dependency,
            },
            ClockPair {
                source: source_delivery,
                target: target_delivery,
            },
        )
    }

    pub(in crate::replay) fn preview_redis_context(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        // A contextual native owner retains its sequence, identity and clock
        // relationships. Resource fields cover every other storage operation.
        if let Some(result) = self.preview_redis_legacy(context, source, actual) {
            return Some(result);
        }
        let keys =
            match self.project_known_redis_keys(context.case, context.command, source, actual) {
                Ok(keys) => keys,
                Err(error) => return Some(Err(error)),
            };
        let actual = keys.as_deref().unwrap_or(actual);
        let ordinary = self.preview_unified_redis(context, source, actual);
        if ordinary.as_ref().is_some_and(Result::is_ok) {
            return ordinary;
        }
        self.preview_redis_hypothesis(context, source, actual)
            .or(ordinary)
            .or_else(|| {
                keys.is_some().then(|| {
                    ensure!(
                        source == actual,
                        "Redis arguments outside accepted key identities changed"
                    );
                    Ok(Decision::default())
                })
            })
    }

    pub(super) fn preview_unified_redis(
        &self,
        context: &RedisRequestContext<'_>,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        self.compare_redis_compiled(context, source, actual)
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
        if args.is_empty() {
            return Ok(());
        }
        let source = args
            .iter()
            .map(evidence::decode)
            .collect::<Result<Vec<_>>>()?;
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
        self.observe_redis_compiled_source(&context, event, &source)
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
        if self.witnesses.is_none() {
            return Ok(ObservationRetention::Unavailable);
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

    pub(super) fn record_unified_response_source(
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
}

pub(super) fn value_index(command: &str, length: usize) -> Option<usize> {
    match (command, length) {
        ("SET", 2..) | ("PUBLISH", 2) => Some(1),
        ("SETEX" | "PSETEX", 3) => Some(2),
        _ => None,
    }
}
