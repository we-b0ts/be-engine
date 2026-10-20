//! Redis command selection with semantic value matching and source-lane order diagnostics.
use super::*;
mod request;
use crate::replay::command_matching::{
    CommandExchangeScope, PreferredMatch, lane_blocked_diagnostic, preferred_match,
    unmatched_diagnostic,
};
use crate::replay::report::command::CommandMatchDiagnostic;

impl RedisReplayState {
    fn arguments_match(&self, exchange: &ReplayExchange, args: &[Vec<u8>]) -> bool {
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
        let (exchange, args) = if exchange.rpc_push.is_some() {
            let Some(comparison) = self.pubsub.comparison_args(exchange, args) else {
                return false;
            };
            rpc_comparison = comparison;
            rpc_exchange = exchange.clone();
            rpc_exchange.args = rpc_comparison.source.clone();
            rpc_exchange.rpc_push = None;
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
        if let Some(result) = self.request_preview(exchange, source, actual) {
            return result.is_ok();
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
        self.pubsub.matches(exchange, args).unwrap_or_else(|| {
            self.publish_rules
                .arguments_match(exchange, args)
                .unwrap_or_else(|| {
                    self.lock_tokens
                        .arguments_match(exchange, &self.exchanges, args)
                        .unwrap_or_else(|| {
                            value::arguments_match(exchange, args, &self.value_rules)
                        })
                })
        })
    }

    pub(in crate::replay) fn configure_lock_tokens(&mut self, rules: &[lock::LockTokenRule]) {
        self.lock_tokens =
            lock::LockTokens::prepare_scoped(&self.exchanges, rules, &self.request_contracts);
    }
    pub(in crate::replay) fn configure_publish(&mut self, rules: Vec<publish::PublishRule>) {
        self.publish_rules
            .configure_scope(self.request_contracts.clone());
        self.publish_rules.configure(rules);
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
        self.request_observed_at = Some(chrono::Utc::now());
        self.request_observation_id = Some(uuid::Uuid::new_v4());
        if let Some(case) = active_case_id {
            match self.request_contracts.record_redis_target(
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
            ) {
                Ok(crate::policy_evidence::ObservationRetention::Unavailable) => {
                    self.request_observation_id = None
                }
                Ok(crate::policy_evidence::ObservationRetention::Retained) => {}
                Err(error) => {
                    tracing::warn!(%error, "failed to preserve independent Redis Target observation")
                }
            }
        }
        let matched = preferred_match(&self.exchanges, active_case_id, |exchange| {
            (exchange.status.is_available()
                || (exchange.reusable_snapshot && exchange.status != ReplayExchangeStatus::Failed))
                && self
                    .connection_scopes
                    .matches(exchange, active_case_id, connection)
                && target_matches(
                    target,
                    &exchange.record.target_host,
                    exchange.record.target_port,
                )
                && exchange.record.resp_version == resp_version
                && exchange.record.database == database
                && normalize_optional(username)
                    == normalize_optional(exchange.record.username.as_deref())
                && exchange.record.command.eq_ignore_ascii_case(command)
                && self.arguments_match(exchange, args)
        });
        let index = match matched {
            PreferredMatch::Matched(index) => index,
            PreferredMatch::LaneBlocked { candidate, blocker } => {
                return Err(lane_blocked_diagnostic(&self.exchanges, candidate, blocker));
            }
            PreferredMatch::NotFound => {
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
                self.capture_publish_candidates(
                    active_case_id,
                    target,
                    connection,
                    resp_version,
                    database,
                    username,
                    command,
                    args,
                );
                self.capture_lock_candidates(
                    active_case_id,
                    target,
                    connection,
                    resp_version,
                    database,
                    username,
                    command,
                    args,
                );
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
        let response = self.exchanges[index].response_bytes().map_err(|error| {
            CommandMatchDiagnostic::EvidenceUnavailable {
                reason: format!("response evidence unavailable: {error:#}"),
            }
        })?;
        let exchange = &self.exchanges[index];
        let unified_delivery = (exchange.record.outcome
            == crate::DependencyExchangeOutcome::Response)
            .then_some(exchange.case_id.as_deref())
            .flatten()
            .and_then(|case| {
                self.request_contracts.prepare_redis_delivery(
                    case,
                    target,
                    database,
                    username,
                    command,
                    &exchange.args,
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
        if unified_delivery.is_some() && exchange.response_time_shift.is_some() {
            return Err(CommandMatchDiagnostic::EvidenceUnavailable {
                reason: "overlapping dependency delivery owners".into(),
            });
        }
        if unified_delivery.is_some()
            && (exchange.reusable_snapshot
                || exchange.shared_rule_id.is_some()
                || exchange.record.cache_snapshot_hit
                || exchange.record.cache_snapshot_rule.is_some())
        {
            return Err(CommandMatchDiagnostic::EvidenceUnavailable {
                reason: "value delivery rules cannot renew shared or snapshot response inventory"
                    .into(),
            });
        }
        let mut rpc_exchange;
        let rpc_comparison;
        let (comparison_exchange, comparison_args) = if exchange.rpc_push.is_some() {
            rpc_comparison = self
                .pubsub
                .comparison_args(exchange, args)
                .expect("selected RPC identities were validated");
            rpc_exchange = exchange.clone();
            rpc_exchange.args = rpc_comparison.source.clone();
            rpc_exchange.rpc_push = None;
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
        let request_decision = self
            .request_preview(&normalized_exchange, &normalized_exchange.args, arguments)
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
        let mut rule_ids = value::used_rules(&normalized_exchange, arguments, &self.value_rules);
        rule_ids.extend(self.lock_tokens.claim(&normalized_exchange, arguments));
        if !request_decision
            .as_ref()
            .is_some_and(|(_, comparison)| comparison.is_some())
        {
            rule_ids.extend(self.publish_rules.claim(&normalized_exchange, arguments));
        }
        if let (Some(case), Some(normalized)) = (exchange.case_id.as_deref(), normalized) {
            self.dynamic_values.commit(case, normalized.decision);
        }
        if let Some((decision, comparison)) = request_decision {
            if let Some(comparison) = comparison {
                rule_ids.extend(self.publish_rules.commit_json(comparison));
            }
            self.request_contracts.commit(decision);
        }
        let rpc_response = self.pubsub.claim(&self.exchanges[index], args);
        let requires_binding =
            self.connection_scopes
                .claim(&self.exchanges[index], active_case_id, connection);
        let exchange = &mut self.exchanges[index];
        let timing = if exchange.reusable_snapshot && exchange.matched_once {
            ReplayExchangeTiming::from_recorded(0, DependencyExchangeOutcome::Response)
        } else {
            exchange.timing
        };
        exchange.status = if exchange.reusable_snapshot {
            exchange.status
        } else if exchange.timing.outcome().is_client_terminated() {
            ReplayExchangeStatus::AwaitingClientTermination
        } else {
            ReplayExchangeStatus::Responding
        };
        Ok(MatchedRedisExchange {
            request_started_at: self.request_observed_at,
            unified_delivery,
            rpc_push: exchange.rpc_push,
            rpc_response,
            publish_duration_ms: exchange.record.duration_ms,
            response_time_shift: exchange.response_time_shift.clone(),
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn match_redis_builtin_failure(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &RedisCommand,
    ) -> Option<MatchedRedisExchange> {
        let index = match preferred_match(&self.exchanges, active_case_id, |exchange| {
            exchange.status.is_available()
                && (exchange.record.response_kind == "error"
                    || exchange.record.outcome.termination().is_some()
                    || exchange.record.outcome.is_client_terminated())
                && self
                    .connection_scopes
                    .matches(exchange, active_case_id, connection)
                && target_matches(
                    target,
                    &exchange.record.target_host,
                    exchange.record.target_port,
                )
                && exchange.record.resp_version == resp_version
                && exchange.record.database == database
                && normalize_optional(username)
                    == normalize_optional(exchange.record.username.as_deref())
                && exchange.record.command.eq_ignore_ascii_case(&command.name)
                && (matches!(command.name.as_str(), "AUTH" | "HELLO")
                    || exchange.args == command.args)
        }) {
            PreferredMatch::Matched(index) => index,
            PreferredMatch::LaneBlocked { .. } | PreferredMatch::NotFound => return None,
        };
        let response = self.exchanges[index].response_bytes().ok()?;
        let requires_binding =
            self.connection_scopes
                .claim(&self.exchanges[index], active_case_id, connection);
        let exchange = &mut self.exchanges[index];
        exchange.status = if exchange.timing.outcome().is_client_terminated() {
            ReplayExchangeStatus::AwaitingClientTermination
        } else {
            ReplayExchangeStatus::Responding
        };
        Some(MatchedRedisExchange {
            request_started_at: self.request_observed_at,
            unified_delivery: None,
            rpc_push: None,
            rpc_response: None,
            publish_duration_ms: exchange.record.duration_ms,
            response_time_shift: None,
            rule_ids: Vec::new(),
            index,
            connection_id: exchange.record.connection_id,
            response,
            timing: exchange.timing,
            requires_binding,
            report: CommandMatchedReport {
                case_id: active_case_id.map(ToOwned::to_owned),
                source: exchange.source,
                index,
                target: target.clone(),
                connection_id: exchange.record.connection_id,
                sequence: exchange.record.sequence,
                command: exchange.record.command.clone(),
                shared_origin: None,
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
        self.source == ReplaySource::Global || self.subscription_alias
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
            || (self.source == ReplaySource::Case
                && self.status == ReplayExchangeStatus::Responding)
    }

    fn preserves_connection_order(&self) -> bool {
        !self.connection_independent
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
