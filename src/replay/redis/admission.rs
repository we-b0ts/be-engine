//! Native Redis request hooks for the shared concurrent admission engine.
use super::*;
use crate::replay::admission::{
    RequestAdmission,
    request::{self, DependencyRequestAdapter, WaitDependency},
};
use crate::replay::report::command::CommandMatchDiagnostic;
use std::time::Duration;
mod lane;
pub(super) mod pipeline;

#[cfg(test)]
mod activity_tests;
#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod tests;

const REFRESH_WAIT: Duration = Duration::from_secs(30);
pub(super) const POOLED_LANE_WAIT: Duration = Duration::from_secs(5);

struct RedisRequest<'a> {
    target: &'a TargetKey,
    client_id: Uuid,
    binding: &'a mut CaseConnectionBinding,
    resp_version: u8,
    database: i64,
    username: Option<&'a str>,
    command: &'a RedisCommand,
    connection: Option<TargetConnection>,
    started: tokio::time::Instant,
    lane_hint: Option<&'a tokio::sync::mpsc::Sender<pipeline::AdjacentPublish>>,
    expected_index: Option<usize>,
}

impl DependencyRequestAdapter for RedisRequest<'_> {
    type Matched = MatchedRedisExchange;
    type Error = CommandMatchDiagnostic;

    fn observe_once(&mut self, state: &mut ReplayState) -> RequestAdmission {
        let case = state.active_case_id.clone();
        self.connection = Some(TargetConnection {
            id: self.client_id,
            bound: self.binding.connection(case.as_deref()),
        });
        state.redis.observe_redis(
            case.as_deref(),
            self.target,
            self.database,
            self.username,
            &self.command.name,
            &self.command.args,
        );
        RequestAdmission::capture(
            state,
            state.redis.request_event_index,
            state.redis.request_observed_at,
            state.redis.request_observation_id,
            state.redis.request_observation_retained,
        )
    }

    fn try_select(
        &mut self,
        state: &mut ReplayState,
        observation: &RequestAdmission,
    ) -> Result<Self::Matched, Self::Error> {
        state.redis.request_event_index = observation.event_index;
        state.redis.request_observed_at = observation.observed_at;
        state.redis.request_observation_id = observation.observation_id;
        state.redis.request_observation_retained = observation.observation_retained;
        let select = |redis: &mut RedisReplayState, expected_index, predecessors| {
            redis.select_redis(
                observation.case.as_deref(),
                self.target,
                self.connection
                    .expect("Redis observation installs its native connection"),
                self.resp_version,
                self.database,
                self.username,
                &self.command.name,
                &self.command.args,
                expected_index,
                predecessors,
            )
        };
        select(&mut state.redis, self.expected_index, None)
            .or_else(|error| {
                if self.lane_hint.is_none() || !lane::enabled(state) {
                    return Err(error);
                }
                let Some(serial) = observation
                    .case
                    .as_deref()
                    .and_then(|case| pipeline::SerialPublish::from_blocker(state, case, &error))
                else {
                    return Err(error);
                };
                select(
                    &mut state.redis,
                    Some(serial.index),
                    Some(serial.predecessors),
                )
            })
            .map(|mut matched| {
                matched.report.target_event_index = observation.event_index;
                matched
            })
    }

    fn wait_dependency<'a>(
        &self,
        state: &'a ReplayState,
        observation: &RequestAdmission,
        error: &Self::Error,
    ) -> Option<WaitDependency<'a>> {
        if lane::enabled(state)
            && lane::pending_predecessor(&state.redis, observation.case.as_deref(), error)
        {
            let deadline = self.started + POOLED_LANE_WAIT;
            if let Some(sender) = self.lane_hint
                && let Ok(permit) = sender.try_reserve()
                && let Some(pair) = pipeline::AdjacentPublish::from_blocker(state, error, deadline)
            {
                permit.send(pair);
            }
            return Some(WaitDependency::changed(&state.redis.lifecycle).until(deadline));
        }
        (pending_delivery(
            &state.redis,
            observation.case.as_deref(),
            &self.command.name,
            observation.event_index,
            error,
        ) || state.redis.pubsub.pending_ingress_reply(
            observation.case.as_deref(),
            self.target,
            &self.command.name,
            &self.command.args,
        ))
        .then(|| WaitDependency::changed(&state.redis.lifecycle))
    }

    fn interrupted(&self, reason: &'static str) -> Self::Error {
        CommandMatchDiagnostic::EvidenceUnavailable {
            reason: reason.into(),
        }
    }

    fn on_selected(
        &mut self,
        state: &mut ReplayState,
        observation: &RequestAdmission,
        matched: &mut Self::Matched,
    ) -> Result<(), Self::Error> {
        if let Some(policy) = &mut state.replay_policy {
            policy.commit_redis_rule_usage(observation.case.as_deref(), &matched.rule_ids);
        }
        if matched.requires_binding {
            self.binding
                .bind(observation.case.as_deref(), matched.connection_id);
        }
        if lane::enabled(state) {
            state.redis.lifecycle.notify_waiters();
        }
        Ok(())
    }

    fn on_rejected(
        &mut self,
        state: &mut ReplayState,
        observation: &RequestAdmission,
        error: &Self::Error,
    ) {
        let hint = redis_authentication_hint(error);
        let report = CommandRequestReport {
            target_observation_id: observation
                .observation_id
                .filter(|_| observation.observation_retained)
                .map(|id| {
                    crate::policy_evidence::target_observation_id(
                        &id.to_string(),
                        crate::policy::Surface::DependencyRequest,
                        crate::policy_evidence::TargetRole::IndependentTargetObservation,
                    )
                }),
            target_event_index: observation.event_index,
            case_id: observation.case.clone(),
            target: self.target.clone(),
            command: self.command.name.clone(),
            request_fingerprint: Some(cross_case::target_fingerprint(
                self.target,
                self.resp_version,
                self.database,
                self.username,
                &self.command.name,
                &self.command.args,
            )),
            reason: hint
                .unwrap_or("no recorded Redis exchange matched target/session/arguments")
                .into(),
            diagnostic: Some(error.clone()),
        };
        state.redis.record_unmatched_request(report);
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn match_command(
    shared: &Arc<Mutex<ReplayState>>,
    target: &TargetKey,
    client_id: Uuid,
    binding: &mut CaseConnectionBinding,
    resp_version: u8,
    database: i64,
    username: Option<&str>,
    command: &RedisCommand,
) -> std::result::Result<MatchedRedisExchange, &'static str> {
    match_command_with_hint(
        shared,
        target,
        client_id,
        binding,
        resp_version,
        database,
        username,
        command,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn match_command_with_hint(
    shared: &Arc<Mutex<ReplayState>>,
    target: &TargetKey,
    client_id: Uuid,
    binding: &mut CaseConnectionBinding,
    resp_version: u8,
    database: i64,
    username: Option<&str>,
    command: &RedisCommand,
    lane_hint: Option<&tokio::sync::mpsc::Sender<pipeline::AdjacentPublish>>,
) -> std::result::Result<MatchedRedisExchange, &'static str> {
    let started = tokio::time::Instant::now();
    request::execute(
        shared,
        &mut RedisRequest {
            target,
            client_id,
            binding,
            resp_version,
            database,
            username,
            command,
            connection: None,
            started,
            lane_hint,
            expected_index: None,
        },
        started + REFRESH_WAIT,
    )
    .await
    .map_err(|error| {
        redis_authentication_hint(&error).unwrap_or("no recorded Redis dependency matched")
    })
}

fn pending_delivery(
    redis: &RedisReplayState,
    case: Option<&str>,
    command: &str,
    event: Option<usize>,
    diagnostic: &CommandMatchDiagnostic,
) -> bool {
    match command {
        "EXPIRE" => redis.pending_initial_refresh(case, diagnostic),
        "SET" => redis.pending_activity_read(case, event, diagnostic),
        _ => false,
    }
}
