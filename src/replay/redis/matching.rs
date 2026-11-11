//! Redis command selection with semantic value matching and source-lane order diagnostics.
use super::*;
use anyhow::ensure;
mod builtin_failure;
mod hypothesis;
mod request;
mod strict;
use crate::replay::command_matching::{
    CommandExchangeScope, PreferredMatch, lane_blocked_diagnostic, preferred_match,
    preferred_match_indexed_with_priority, unmatched_diagnostic,
};
use crate::replay::report::command::CommandMatchDiagnostic;

impl RedisReplayState {
    pub(super) fn arguments_match(&self, exchange: &ReplayExchange, args: &[Vec<u8>]) -> bool {
        self.arguments_match_inner(exchange, args, true)
    }

    pub(super) fn observation_arguments_match(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> bool {
        self.arguments_match_inner(exchange, args, false)
    }

    fn arguments_match_inner(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
        allow_hypotheses: bool,
    ) -> bool {
        if self.activity_refresh.owns(exchange) {
            return false;
        }
        let original_source = exchange.args.as_slice();
        let original_actual = args;
        if exchange.source == ReplaySource::Case
            && exchange.shared_rule_id.is_none()
            && let Some(case) = exchange.case_id.as_deref()
        {
            let target = TargetKey {
                host: exchange.record.target_host.clone(),
                port: exchange.record.target_port,
            };
            self.request_contracts.record_unified_request(
                &crate::replay::policy::request_contract::RedisRequestContext {
                    case,
                    target: &target,
                    database: exchange.record.database,
                    username: exchange.record.username.as_deref(),
                    command: &exchange.record.command,
                    recorded_at: exchange.record.started_at(),
                    actual_at: self.request_observed_at,
                    connection_id: Some(exchange.record.connection_id),
                    sequence: Some(exchange.record.sequence),
                    observation_id: self.request_observation_id,
                },
                &exchange.args,
                Some(args),
            );
        }
        let mut rpc_exchange;
        let rpc_comparison;
        let (exchange, args) = if self.pubsub.is_adapter_source(exchange) {
            let Some(comparison) = self.pubsub.comparison_args(exchange, args) else {
                return false;
            };
            rpc_comparison = comparison;
            rpc_exchange = exchange.clone();
            rpc_exchange.args = rpc_comparison.source.clone();
            rpc_exchange.rpc_push = None;
            rpc_exchange.record.rpc_callback_capture = None;
            (&rpc_exchange, rpc_comparison.actual.as_slice())
        } else {
            (exchange, args)
        };
        let normalized =
            if exchange.source == ReplaySource::Case && exchange.shared_rule_id.is_none() {
                match self
                    .dynamic_values
                    .redis_with_identity(
                        exchange.case_id.as_deref(),
                        &TargetKey {
                            host: exchange.record.target_host.clone(),
                            port: exchange.record.target_port,
                        },
                        crate::replay::policy::dynamic_values::RedisIdentity {
                            database: exchange.record.database,
                            username: exchange.record.username.as_deref(),
                        },
                        &exchange.record.command,
                        &exchange.args,
                        args,
                    )
                    .transpose()
                {
                    Ok(normalized) => normalized,
                    Err(_) => return false,
                }
            } else {
                None
            };
        let source = normalized
            .as_ref()
            .map_or(exchange.args.as_slice(), |n| n.source.as_slice());
        let actual = normalized.as_ref().map_or(args, |n| n.actual.as_slice());
        if let Some(result) = self.request_preview_with_hypotheses(
            exchange,
            source,
            actual,
            original_source,
            original_actual,
            allow_hypotheses,
        ) {
            return result
                .and_then(|mut decision| {
                    ensure!(
                        allow_hypotheses || !decision.is_provisional(),
                        "a key hypothesis cannot select a native state-observation owner"
                    );
                    if let (Some(case), Some(normalized)) =
                        (exchange.case_id.as_deref(), normalized.as_ref())
                    {
                        self.dynamic_values.join_identities(
                            case,
                            &normalized.decision,
                            &mut decision,
                        )?;
                    }
                    Ok(())
                })
                .is_ok();
        }
        if let Some(normalized) = normalized {
            let mut comparison = exchange.clone();
            comparison.args = normalized.source;
            self.arguments_match_plain(&comparison, &normalized.actual)
        } else {
            self.arguments_match_plain(exchange, args)
        }
    }

    fn arguments_match_plain(&self, exchange: &ReplayExchange, args: &[Vec<u8>]) -> bool {
        let normalized = match super::expiration::normalize(
            &exchange.record.command,
            &exchange.args,
            args,
            crate::value_contract::time::ClockPair {
                source: exchange.record.started_at(),
                target: self.request_observed_at,
            },
        ) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let args = normalized.as_deref().unwrap_or(args);
        // Protocol identities were checked and translated by comparison_args
        // before this private comparison copy was built. Do not bind them twice.
        value::arguments_match(exchange, args)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn match_redis(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
    ) -> std::result::Result<MatchedRedisExchange, CommandMatchDiagnostic> {
        self.observe_redis(active_case_id, target, database, username, command, args);
        self.select_redis(
            active_case_id,
            target,
            connection,
            resp_version,
            database,
            username,
            command,
            args,
            None,
            None,
            false,
        )
        .map(|mut matched| {
            matched.report.target_event_index = self.request_event_index;
            matched
        })
    }

    pub(super) fn observe_redis(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
    ) {
        // Allocate before selection under the replay mutex. Delivery completion
        // and success-detail retention must never determine request ordering.
        self.events.request_order.reserve(active_case_id);
        self.request_event_index = self.events.request_order.latest(active_case_id);
        self.request_observed_at = Some(chrono::Utc::now());
        self.request_observation_id = Some(uuid::Uuid::new_v4());
        let retention = if let Some(case) =
            active_case_id.filter(|_| self.request_contracts.retains_value_witnesses())
        {
            self.request_contracts.record_redis_target(
                &crate::replay::policy::request_contract::RedisRequestContext {
                    case,
                    target,
                    database,
                    username,
                    command,
                    recorded_at: None,
                    actual_at: self.request_observed_at,
                    connection_id: None,
                    sequence: None,
                    observation_id: self.request_observation_id,
                },
                args,
            )
        } else if let Some(observations) = &self.target_observations {
            observations.record(
                self.request_observation_id.unwrap(),
                active_case_id,
                Some(crate::policy::Resource {
                    protocol: crate::policy::Protocol::Redis,
                    endpoint: crate::policy::Endpoint {
                        host: target.host.clone(),
                        port: target.port,
                    },
                    database: Some(crate::policy::Database::Index(database)),
                    username: username.map(str::to_owned),
                }),
                command,
                self.request_observed_at.unwrap(),
                &serde_json::to_vec(args).expect("Redis native arguments are serializable"),
            )
        } else {
            Ok(crate::policy_evidence::ObservationRetention::Unavailable)
        };
        self.request_observation_retained = self.target_observations.as_ref().map_or_else(
            || {
                matches!(
                    &retention,
                    Ok(crate::policy_evidence::ObservationRetention::Retained)
                )
            },
            |observations| observations.retained(&retention),
        );
        if matches!(
            &retention,
            Ok(crate::policy_evidence::ObservationRetention::Unavailable)
        ) {
            self.request_observation_id = None;
        }
        if retention.is_err() {
            tracing::warn!(
                "independent Redis Target observation unavailable; inspect target_observation_coverage_error"
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn select_redis(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
        expected_index: Option<usize>,
        serial: Option<super::admission::pipeline::SerialPublish>,
        fast_socketio: bool,
    ) -> std::result::Result<MatchedRedisExchange, CommandMatchDiagnostic> {
        self.candidates.register(&self.exchanges);
        if let Some(case) = active_case_id {
            self.prepare_observations(case).map_err(|error| {
                CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: format!("state-observation Source proof failed: {error:#}"),
                }
            })?;
            self.prepare_read_commutation(case).map_err(|error| {
                CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: format!("read commutation Source proof failed: {error:#}"),
                }
            })?;
            self.prepare_append_case(case).map_err(append::diagnostic)?;
            self.prepare_activity_case(case).map_err(|error| {
                CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: format!("activity refresh Source proof failed: {error:#}"),
                }
            })?;
            if let Some(matched) = self.match_initial_expiry(
                case,
                target,
                connection,
                resp_version,
                database,
                username,
                command,
                args,
            )? {
                return Ok(matched);
            }
            if let Some(matched) = self.match_activity(
                case,
                target,
                connection,
                resp_version,
                database,
                username,
                command,
                args,
            )? {
                return Ok(matched);
            }
            if command == "APPEND"
                && let Some(matched) = self
                    .match_append(
                        case,
                        target,
                        connection,
                        resp_version,
                        database,
                        username,
                        args,
                    )
                    .map_err(append::diagnostic)?
            {
                return Ok(matched);
            }
        }
        let observation = self.observation_candidate(
            active_case_id,
            target,
            connection,
            resp_version,
            database,
            username,
            command,
            args,
        )?;
        let pre_match_enabled = self.request_contracts.pre_match_enabled();
        let mut matched = observation
            .map(PreferredMatch::Matched)
            .unwrap_or(PreferredMatch::NotFound);
        for allow_pre_match in [false, true] {
            if !matches!(matched, PreferredMatch::NotFound)
                || allow_pre_match && (!pre_match_enabled || expected_index.is_some())
            {
                break;
            }
            self.request_contracts
                .configure_pre_match(allow_pre_match && pre_match_enabled);
            if allow_pre_match {
                matched = self.unique_hypothesis_match(
                    active_case_id,
                    target,
                    connection,
                    resp_version,
                    database,
                    username,
                    command,
                    args,
                )?;
                continue;
            }
            matched = self.match_strict_redis(
                active_case_id,
                target,
                connection,
                resp_version,
                database,
                username,
                command,
                args,
                expected_index,
                serial.as_ref().map(|serial| serial.first_blocker),
                fast_socketio,
            );
        }
        self.request_contracts
            .configure_pre_match(pre_match_enabled);
        let index = match matched {
            PreferredMatch::Matched(index) => index,
            PreferredMatch::LaneBlocked { candidate, blocker } => {
                return Err(lane_blocked_diagnostic(&self.exchanges, candidate, blocker));
            }
            PreferredMatch::NotFound => {
                if let Some(expected) = self.lifecycle.sequence.expected_index() {
                    return Err(CommandMatchDiagnostic::EvidenceUnavailable {
                        reason: expected.map_or_else(|| "recorded dependency predecessor is pending".into(),
                            |index| format!("request differs from next recorded Redis dependency at index {index}")),
                    });
                }
                if let Some(expected) = expected_index {
                    let exchange = &self.exchanges[expected];
                    let fields = redis_mismatch_fields(
                        exchange,
                        target,
                        self.connection_scopes
                            .matches(exchange, active_case_id, connection),
                        resp_version,
                        database,
                        username,
                        command,
                        self.arguments_match(exchange, args),
                    );
                    return Err(CommandMatchDiagnostic::Mismatch {
                        fields: fields.into_iter().map(str::to_owned).collect(),
                    });
                }
                for exchange in self.exchanges.iter().filter(|exchange| {
                    exchange.source == ReplaySource::Case
                        && exchange.shared_rule_id.is_none()
                        && exchange.case_id.as_deref() == active_case_id
                        && exchange.status.is_available()
                        && target_matches(
                            target,
                            &exchange.record.target_host,
                            exchange.record.target_port,
                        )
                        && exchange.record.resp_version == resp_version
                        && exchange.record.database == database
                        && normalize_optional(username)
                            == normalize_optional(exchange.record.username.as_deref())
                        && exchange.record.command == command
                }) {
                    if let Some(case) = active_case_id {
                        self.request_contracts.observe_redis(
                            case,
                            target,
                            database,
                            command,
                            &exchange.args,
                            args,
                            crate::replay::assertion::RequestTimes {
                                source: exchange.record.started_at(),
                                target: self.request_observed_at,
                            },
                        );
                        self.dynamic_values.observe_redis(
                            case,
                            target,
                            database,
                            command,
                            &exchange.args,
                            args,
                        );
                    }
                }
                self.capture_value_candidates(
                    active_case_id,
                    target,
                    connection,
                    resp_version,
                    database,
                    username,
                    command,
                    args,
                );
                // Prefer the exact request whose stateful connection is
                // unavailable over a different key with a similar signature.
                // Otherwise a pool/session conflict can look like an argument bug.
                let connection_conflict =
                    preferred_match(&self.exchanges, active_case_id, |exchange| {
                        exchange.is_available()
                            && redis_mismatch_fields(
                                exchange,
                                target,
                                self.connection_scopes.matches(
                                    exchange,
                                    active_case_id,
                                    connection,
                                ),
                                resp_version,
                                database,
                                username,
                                command,
                                self.arguments_match(exchange, args),
                            )
                            .as_slice()
                                == ["connection"]
                    });
                if matches!(connection_conflict, PreferredMatch::Matched(_)) {
                    return Err(CommandMatchDiagnostic::Mismatch {
                        fields: vec!["connection".to_string()],
                    });
                }
                return Err(unmatched_diagnostic(
                    &self.exchanges,
                    active_case_id,
                    |exchange| {
                        redis_mismatch_fields(
                            exchange,
                            target,
                            self.connection_scopes
                                .matches(exchange, active_case_id, connection),
                            resp_version,
                            database,
                            username,
                            command,
                            self.arguments_match(exchange, args),
                        )
                    },
                ));
            }
        };
        if expected_index.is_some_and(|expected| expected != index) {
            return Err(CommandMatchDiagnostic::EvidenceUnavailable {
                reason: "pipelined Redis predecessor selected a different Source occurrence".into(),
            });
        }
        self.check_observation_mutation(index)?;
        self.check_activity_mutation(index)?;
        self.check_append_barrier(index, args)
            .map_err(append::diagnostic)?;
        let response = self.exchanges[index].response_bytes().map_err(|error| {
            CommandMatchDiagnostic::EvidenceUnavailable {
                reason: format!("response evidence unavailable: {error:#}"),
            }
        })?;
        let exchange = &self.exchanges[index];
        let read_back_context = crate::replay::policy::request_contract::RedisRequestContext {
            case: exchange.case_id.as_deref().unwrap_or_default(),
            target,
            database,
            username,
            command,
            recorded_at: exchange.record.started_at(),
            actual_at: self.request_observed_at,
            connection_id: Some(exchange.record.connection_id),
            sequence: Some(exchange.record.sequence),
            observation_id: self.request_observation_id,
        };
        let read_back_eligible = exchange.source == ReplaySource::Case
            && exchange.shared_rule_id.is_none()
            && !exchange.reusable_snapshot
            && !exchange.record.cache_snapshot_hit
            && exchange.record.cache_snapshot_rule.is_none()
            && exchange.record.outcome == crate::DependencyExchangeOutcome::Response;
        let time_read = if read_back_eligible {
            self.request_contracts
                .prepare_redis_time_read(
                    &read_back_context,
                    &exchange.args,
                    args,
                    &response,
                    exchange.record.timestamp,
                )
                .map_err(|error| CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: format!("stored field read provenance failed: {error:#}"),
                })?
        } else {
            None
        };
        let time_write = if read_back_eligible {
            self.request_contracts
                .prepare_redis_time_write(
                    &read_back_context,
                    &exchange.args,
                    args,
                    &response,
                    exchange.record.timestamp,
                )
                .map_err(|error| CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: format!("stored write provenance failed: {error:#}"),
                })?
        } else {
            None
        };
        let (read_back, read_back_write) = if read_back_eligible {
            (
                self.request_contracts
                    .prepare_redis_read_back(&read_back_context, &exchange.args, args, &response)
                    .map_err(|error| CommandMatchDiagnostic::EvidenceUnavailable {
                        reason: format!("read_back response failed: {error:#}"),
                    })?,
                self.request_contracts
                    .preview_redis_read_back_write(
                        &read_back_context,
                        &exchange.args,
                        args,
                        &response,
                        exchange.record.timestamp,
                    )
                    .map_err(|error| CommandMatchDiagnostic::EvidenceUnavailable {
                        reason: format!("read_back write failed: {error:#}"),
                    })?,
            )
        } else {
            (None, Default::default())
        };
        let unified_delivery = (exchange.record.outcome
            == crate::DependencyExchangeOutcome::Response)
            .then_some(active_case_id.or(exchange.case_id.as_deref()))
            .flatten()
            .and_then(|case| {
                self.request_contracts.prepare_redis_delivery(
                    case,
                    exchange.case_id.as_deref().unwrap_or(case),
                    target,
                    database,
                    username,
                    command,
                    &exchange.args,
                    args,
                    &response,
                    exchange.record.timestamp,
                    self.request_observed_at,
                    exchange.record.started_at(),
                    exchange.record.connection_id,
                    exchange.record.sequence,
                )
            })
            .transpose()
            .map_err(|error| CommandMatchDiagnostic::EvidenceUnavailable {
                reason: format!("response contract failed: {error:#}"),
            })?;
        if unified_delivery.is_some()
            && (exchange.reusable_snapshot
                || exchange.record.cache_snapshot_hit
                || exchange.record.cache_snapshot_rule.is_some())
        {
            return Err(CommandMatchDiagnostic::EvidenceUnavailable {
                reason: "value delivery rules cannot renew snapshot response inventory".into(),
            });
        }
        let mut rpc_exchange;
        let rpc_comparison;
        let (comparison_exchange, comparison_args) = if self.pubsub.is_adapter_source(exchange) {
            rpc_comparison = self
                .pubsub
                .comparison_args(exchange, args)
                .expect("selected RPC identities were validated");
            rpc_exchange = exchange.clone();
            rpc_exchange.args = rpc_comparison.source.clone();
            rpc_exchange.rpc_push = None;
            rpc_exchange.record.rpc_callback_capture = None;
            (&rpc_exchange, rpc_comparison.actual.as_slice())
        } else {
            (exchange, args)
        };
        let normalized = (exchange.source == ReplaySource::Case
            && exchange.shared_rule_id.is_none())
        .then(|| {
            self.dynamic_values.redis_with_identity(
                exchange.case_id.as_deref(),
                &TargetKey {
                    host: exchange.record.target_host.clone(),
                    port: exchange.record.target_port,
                },
                crate::replay::policy::dynamic_values::RedisIdentity {
                    database: exchange.record.database,
                    username: exchange.record.username.as_deref(),
                },
                &exchange.record.command,
                &comparison_exchange.args,
                comparison_args,
            )
        })
        .flatten()
        .transpose()
        .expect("selected Redis arguments were validated");
        let mut normalized_exchange = comparison_exchange.clone();
        let arguments = if let Some(normalized) = &normalized {
            normalized_exchange.args = normalized.source.clone();
            normalized.actual.as_slice()
        } else {
            comparison_args
        };
        let mut request_decision = self
            .request_preview(
                &normalized_exchange,
                &normalized_exchange.args,
                arguments,
                &exchange.args,
                args,
            )
            .transpose()
            .expect("selected Redis request contract was validated");
        let response = if matches!(command, "SUBSCRIBE" | "UNSUBSCRIBE")
            && exchange.args.first() != args.first()
            && !response.starts_with(b"-")
        {
            crate::redis::translate_subscription_confirmation(
                &crate::redis::RedisCommand {
                    name: command.into(),
                    args: exchange.args.clone(),
                },
                &response,
                &args[0],
            )
            .map_err(|error| CommandMatchDiagnostic::EvidenceUnavailable {
                reason: format!("subscription confirmation translation failed: {error:#}"),
            })?
        } else {
            response
        };
        let response = read_back
            .as_ref()
            .map_or(response, |prepared| prepared.response.clone());
        let mut identities = crate::replay::policy::request_contract::Decision::default();
        if let (Some(case), Some(normalized)) = (exchange.case_id.as_deref(), normalized.as_ref()) {
            self.dynamic_values
                .join_identities(case, &normalized.decision, &mut identities)
                .map_err(|error| CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: format!("native identity correspondence failed: {error:#}"),
                })?;
        }
        if let Some(decision) = &mut request_decision
            && let Some(identity) = decision.identity.take()
        {
            self.request_contracts
                .merge_identity_decision(&mut identities, identity)
                .map_err(|error| CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: format!("combined identity correspondence failed: {error:#}"),
                })?;
        }
        self.request_contracts.commit(identities).map_err(|error| {
            CommandMatchDiagnostic::EvidenceUnavailable {
                reason: format!("identity correspondence commit failed: {error:#}"),
            }
        })?;
        self.request_contracts
            .commit_redis_read_back_write(read_back_write)
            .map_err(|error| CommandMatchDiagnostic::EvidenceUnavailable {
                reason: format!("read_back write commit failed: {error:#}"),
            })?;
        let mut rule_ids = Vec::new();
        rule_ids.extend(exchange.read_commutation_rule.clone());
        rule_ids.extend(self.observations.native_rule(index).map(str::to_owned));
        if let (Some(case), Some(normalized)) = (exchange.case_id.as_deref(), normalized) {
            self.dynamic_values
                .commit_after_identities(case, normalized.decision);
        }
        if let Some(decision) = request_decision {
            self.request_contracts.commit(decision).map_err(|error| {
                CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: format!("Redis resource relationship commit failed: {error:#}"),
                }
            })?;
        }
        let rpc_response = self.pubsub.claim(&self.exchanges[index], args);
        let adapter_echo = self.pubsub.prepare_echo(&self.exchanges[index], args);
        let requires_binding =
            self.connection_scopes
                .claim(&self.exchanges[index], active_case_id, connection);
        let observation = self.reserve_observation(index, args);
        let refresh = self
            .reserve_activity_mutation(index, args)
            .map_err(|error| CommandMatchDiagnostic::EvidenceUnavailable {
                reason: format!("activity lifecycle failed: {error:#}"),
            })?;
        self.record_observation_mutation(index, args);
        let exchange = &mut self.exchanges[index];
        let timing =
            if (exchange.reusable_snapshot || observation.is_some()) && exchange.matched_once {
                ReplayExchangeTiming::from_recorded(0, DependencyExchangeOutcome::Response)
            } else {
                exchange.timing
            };
        let claim = if exchange.reusable_snapshot {
            Claim::Native(NativeClaimKind::ReusableSnapshot)
        } else if observation.is_some() {
            Claim::Native(NativeClaimKind::StateObservation)
        } else {
            let kind = if exchange.timing.outcome().is_client_terminated()
                && !exchange.record.lifecycle_cleanup
            {
                ClaimKind::ClientTermination
            } else {
                ClaimKind::Response
            };
            let ticket = self
                .lifecycle
                .claim(index, &mut exchange.status, kind)
                .ok_or_else(|| CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: "finite Redis exchange was already claimed".into(),
                })?;
            exchange.claim = Some(ticket.observer());
            Claim::Finite(ticket)
        };
        if let Some(serial) = serial {
            exchange.serial_predecessors = Some(serial.predecessors);
            exchange.serial_broadcast = serial.broadcast;
        } else {
            exchange.serial_predecessors = None;
            exchange.serial_broadcast = None;
        }
        if exchange.record.command.eq_ignore_ascii_case("PUBLISH") {
            // A notification may depend on this accepted request's identity,
            // before either its response or a related RPC callback completes.
            self.lifecycle.notify_waiters();
        }
        Ok(MatchedRedisExchange {
            claim,
            refresh,
            observation,
            append: None,
            read_back,
            time_read,
            time_write,
            unified_delivery,
            rpc_push: exchange.rpc_push,
            rpc_response,
            adapter_echo,
            publish_duration_ms: exchange.record.duration_ms,
            rule_ids,
            index,
            connection_id: exchange.record.connection_id,
            response,
            timing,
            requires_binding,
            report: CommandMatchedReport {
                case_id: if exchange.subscription_alias && exchange.source == ReplaySource::Case {
                    exchange.case_id.clone()
                } else {
                    active_case_id.map(ToOwned::to_owned)
                },
                source: exchange.source,
                index,
                target: target.clone(),
                connection_id: exchange.record.connection_id,
                sequence: exchange.record.sequence,
                command: exchange.record.command.clone(),
                shared_origin: exchange.shared_rule_id.as_ref().map(|rule_id| {
                    crate::replay::report::command::SharedCommandOrigin {
                        rule_id: rule_id.clone(),
                        case_id: exchange
                            .case_id
                            .clone()
                            .expect("shared Redis exchange has origin case"),
                    }
                }),
                target_event_index: None,
            },
        })
    }
}

impl CommandExchangeScope for ReplayExchange {
    fn source(&self) -> ReplaySource {
        self.source
    }

    fn available_in_global_scope(&self) -> bool {
        self.source.is_run_owned() || self.subscription_alias
    }

    fn case_id(&self) -> Option<&str> {
        self.case_id.as_deref()
    }

    fn connection_id(&self) -> Uuid {
        self.record.connection_id
    }

    fn sequence(&self) -> u64 {
        self.record.sequence
    }

    fn command(&self) -> &str {
        &self.record.command
    }

    fn is_available(&self) -> bool {
        self.status.is_available()
            || (self.reusable_snapshot && self.status != ReplayExchangeStatus::Failed)
    }

    fn is_consumed(&self) -> bool {
        self.status.is_consumed() || (self.reusable_snapshot && self.matched_once)
    }

    fn satisfies_lane_order(&self) -> bool {
        // A case request has been claimed under the replay mutex before its
        // response is delivered. A pooled next request may arrive after bytes
        // reach the client but before delivery bookkeeping reacquires the mutex.
        // Unclaimed, failed and client-termination exchanges remain blockers.
        self.is_consumed()
            || self.serial_predecessors.is_none()
                && if let Some(ticket) = &self.claim {
                    self.source == ReplaySource::Case && ticket.satisfies(Barrier::Admitted)
                } else {
                    Lifecycle::satisfies(self.status, self.source, Barrier::Admitted)
                }
    }

    fn preserves_connection_order(&self) -> bool {
        !self.connection_independent
            && self.read_commutation_rule.is_none()
            && self.observation_rule.is_none()
    }
}

#[allow(clippy::too_many_arguments)]
fn redis_mismatch_fields(
    exchange: &ReplayExchange,
    target: &TargetKey,
    connection_matches: bool,
    resp_version: u8,
    database: i64,
    username: Option<&str>,
    command: &str,
    arguments_match: bool,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if !connection_matches {
        fields.push("connection");
    }
    if !target_matches(
        target,
        &exchange.record.target_host,
        exchange.record.target_port,
    ) {
        fields.push("target");
    }
    if exchange.record.resp_version != resp_version || exchange.record.database != database {
        fields.push("session");
    }
    let recorded_username = normalize_optional(exchange.record.username.as_deref());
    let target_username = normalize_optional(username);
    if recorded_username != target_username {
        fields.push(
            if recorded_username.is_some() && target_username.is_none() {
                "authentication_not_observed"
            } else {
                "username"
            },
        );
    }
    if !exchange.record.command.eq_ignore_ascii_case(command) {
        fields.push("command");
    }
    if !arguments_match {
        fields.push("arguments");
    }
    fields
}

pub(super) fn redis_authentication_hint(
    diagnostic: &CommandMatchDiagnostic,
) -> Option<&'static str> {
    // Only attribute an otherwise matching exchange to missing authentication.
    // A username difference cannot prove that the application omitted a password.
    match diagnostic {
        CommandMatchDiagnostic::Mismatch { fields }
            if fields.as_slice() == ["authentication_not_observed"] =>
        {
            Some(
                "Redis authentication state mismatch: the recorded connection has an authenticated username, but target authentication was not observed. Check password configuration and whether it is passed to the Redis client.",
            )
        }
        _ => None,
    }
}
