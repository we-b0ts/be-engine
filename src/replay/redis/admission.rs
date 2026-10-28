//! Await initial-refresh delivery fences without consuming or re-observing requests.
use super::*;
use crate::replay::report::command::CommandMatchDiagnostic;
use std::time::Duration;

#[cfg(test)]
mod tests;

// A stalled predecessor must not retain a connection indefinitely. Case shutdown
// is checked independently, including when no delivery notification arrives.
const REFRESH_WAIT: Duration = Duration::from_secs(30);

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
    let mut state = shared.lock().await;
    let case = state.active_case_id.clone();
    let connection = TargetConnection {
        id: client_id,
        bound: binding.connection(case.as_deref()),
    };
    let mut result = state.redis.match_redis(
        case.as_deref(),
        target,
        connection,
        resp_version,
        database,
        username,
        &command.name,
        &command.args,
    );
    let event = state.redis.request_event_index;
    let observed_at = state.redis.request_observed_at;
    let observation = state.redis.request_observation_id;
    let deadline = tokio::time::Instant::now() + REFRESH_WAIT;
    while let Err(diagnostic) = &result {
        if command.name != "EXPIRE"
            || !state
                .redis
                .pending_initial_refresh(case.as_deref(), diagnostic)
        {
            break;
        }
        let changed = state.redis.delivery_changed.clone().notified_owned();
        tokio::pin!(changed);
        // Register while holding the state mutex so completion cannot race registration.
        changed.as_mut().enable();
        drop(state);
        tokio::select! {
            _ = &mut changed => {},
            _ = tokio::time::sleep(Duration::from_millis(100)) => {},
        }
        state = shared.lock().await;
        let reason = if state.active_case_id != case
            || state.finalized_at.is_some()
            || state.target_session_stopped
            || state.async_case_quiescing()
            || case
                .as_ref()
                .is_some_and(|c| state.target_stop_prepared.contains(c))
        {
            Some("Redis case stopped while awaiting initial refresh predecessors")
        } else if tokio::time::Instant::now() >= deadline {
            Some("Redis initial refresh predecessor delivery wait timed out")
        } else {
            None
        };
        if let Some(reason) = reason {
            result = Err(CommandMatchDiagnostic::EvidenceUnavailable {
                reason: reason.into(),
            });
            break;
        }
        if state
            .redis
            .pending_initial_refresh(case.as_deref(), diagnostic)
        {
            continue;
        }
        state.redis.request_event_index = event;
        state.redis.request_observed_at = observed_at;
        state.redis.request_observation_id = observation;
        result = state.redis.select_redis(
            case.as_deref(),
            target,
            connection,
            resp_version,
            database,
            username,
            &command.name,
            &command.args,
        );
        if let Ok(matched) = &mut result {
            matched.report.target_event_index = event;
        }
    }
    match result {
        Ok(matched) => {
            if let Some(policy) = &mut state.replay_policy {
                policy.commit_redis_rule_usage(case.as_deref(), &matched.rule_ids);
            }
            if matched.requires_binding {
                binding.bind(case.as_deref(), matched.connection_id);
            }
            Ok(matched)
        }
        Err(diagnostic) => {
            let hint = redis_authentication_hint(&diagnostic);
            if let Some(case) = &case {
                state.redis.events.dirty_case_ids.insert(case.clone());
            }
            state.redis.events.unmatched.push(CommandRequestReport {
                target_event_index: event,
                case_id: case,
                target: target.clone(),
                command: command.name.clone(),
                request_fingerprint: Some(cross_case::target_fingerprint(
                    target,
                    resp_version,
                    database,
                    username,
                    &command.name,
                    &command.args,
                )),
                reason: hint
                    .unwrap_or("no recorded Redis exchange matched target/session/arguments")
                    .into(),
                diagnostic: Some(diagnostic),
            });
            Err(hint.unwrap_or("no recorded Redis dependency matched"))
        }
    }
}
