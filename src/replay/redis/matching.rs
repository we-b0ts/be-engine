//! Redis command selection with semantic value matching and source-lane order diagnostics.
use super::*;
use crate::replay::command_matching::{
    CommandExchangeScope, PreferredMatch, lane_blocked_diagnostic, preferred_match,
    unmatched_diagnostic,
};
use crate::replay::report::command::CommandMatchDiagnostic;

impl RedisReplayState {
    fn arguments_match(&self, exchange: &ReplayExchange, args: &[Vec<u8>]) -> bool {
        if exchange.rpc_push.is_some() {
            return self.pubsub.matches(exchange, args).unwrap_or(false);
        }
        let normalized =
            if exchange.source == ReplaySource::Case && exchange.shared_rule_id.is_none() {
                match self
                    .dynamic_values
                    .redis(
                        exchange.case_id.as_deref(),
                        &TargetKey {
                            host: exchange.record.target_host.clone(),
                            port: exchange.record.target_port,
                        },
                        exchange.record.database,
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
        if exchange.source == ReplaySource::Case
            && exchange.shared_rule_id.is_none()
            && let Some(case) = exchange.case_id.as_deref()
            && let Some(result) = self.request_contracts.preview_redis(
                case,
                &TargetKey {
                    host: exchange.record.target_host.clone(),
                    port: exchange.record.target_port,
                },
                exchange.record.database,
                &exchange.record.command,
                source,
                actual,
            )
        {
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
        self.lock_tokens = lock::LockTokens::prepare(&self.exchanges, rules);
    }
    pub(in crate::replay) fn configure_publish(&mut self, rules: Vec<publish::PublishRule>) {
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
        let exchange = &self.exchanges[index];
        let normalized = (exchange.source == ReplaySource::Case
            && exchange.shared_rule_id.is_none())
        .then(|| {
            self.dynamic_values.redis(
                exchange.case_id.as_deref(),
                &TargetKey {
                    host: exchange.record.target_host.clone(),
                    port: exchange.record.target_port,
                },
                exchange.record.database,
                &exchange.record.command,
                &exchange.args,
                args,
            )
        })
        .flatten()
        .transpose()
        .expect("selected Redis arguments were validated");
        let mut normalized_exchange = exchange.clone();
        let arguments = if let Some(normalized) = &normalized {
            normalized_exchange.args = normalized.source.clone();
            normalized.actual.as_slice()
        } else {
            args
        };
        let request_decision = (exchange.source == ReplaySource::Case
            && exchange.shared_rule_id.is_none())
        .then(|| {
            exchange.case_id.as_deref().and_then(|case| {
                self.request_contracts.preview_redis(
                    case,
                    target,
                    database,
                    command,
                    &normalized_exchange.args,
                    arguments,
                )
            })
        })
        .flatten()
        .transpose()
        .expect("selected Redis request contract was validated");
        let mut rule_ids = value::used_rules(&normalized_exchange, arguments, &self.value_rules);
        rule_ids.extend(self.lock_tokens.claim(&normalized_exchange, arguments));
        rule_ids.extend(self.publish_rules.claim(&normalized_exchange, arguments));
        if let (Some(case), Some(normalized)) = (exchange.case_id.as_deref(), normalized) {
            self.dynamic_values.commit(case, normalized.decision);
        }
        if let Some(decision) = request_decision {
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
            rpc_push: exchange.rpc_push,
            rpc_response,
            publish_duration_ms: exchange.record.duration_ms,
            response_time_shift: exchange.response_time_shift.clone(),
            rule_ids,
            index,
            connection_id: exchange.record.connection_id,
            response: exchange.response.clone(),
            timing,
            requires_binding,
            report: CommandMatchedReport {
                case_id: active_case_id.map(ToOwned::to_owned),
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
                && exchange.record.response_kind == "error"
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
            rpc_push: None,
            rpc_response: None,
            publish_duration_ms: exchange.record.duration_ms,
            response_time_shift: None,
            rule_ids: Vec::new(),
            index,
            connection_id: exchange.record.connection_id,
            response: exchange.response.clone(),
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
