//! Proof for reading one adjacent Socket.IO publish from a blocked Redis stream.
use super::*;
use crate::redis::socketio_rpc;
use crate::replay::command_matching::PreferredMatch;
use tokio::time::Instant;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(in crate::replay::redis) struct AdjacentPublish {
    epoch: u64,
    deadline: Instant,
    case: String,
    earlier: usize,
    later: usize,
}

impl AdjacentPublish {
    pub(super) fn from_blocker(
        state: &ReplayState,
        error: &CommandMatchDiagnostic,
        deadline: Instant,
    ) -> Option<Self> {
        let CommandMatchDiagnostic::LaneBlocked {
            candidate,
            blocked_by,
        } = error
        else {
            return None;
        };
        if candidate.command != "PUBLISH"
            || blocked_by.command != "PUBLISH"
            || blocked_by.sequence.checked_add(1) != Some(candidate.sequence)
        {
            return None;
        }
        let case = state.active_case_id.as_deref()?;
        let earlier = lane::ordinary_slot(&state.redis, case, blocked_by)?;
        let later = lane::ordinary_slot(&state.redis, case, candidate)?;
        let first = &state.redis.exchanges[earlier];
        let second = &state.redis.exchanges[later];
        let first_namespace = namespace(first)?;
        let second_namespace = namespace(second)?;
        (first.args.first() == second.args.first() && first_namespace != second_namespace).then(
            || Self {
                epoch: state.admission_epoch,
                deadline,
                case: case.to_owned(),
                earlier,
                later,
            },
        )
    }

    pub(in crate::replay::redis) fn later(&self) -> usize {
        self.later
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay::redis) async fn admit_predecessor(
        &self,
        shared: &Arc<Mutex<ReplayState>>,
        target: &TargetKey,
        client_id: Uuid,
        mut binding: CaseConnectionBinding,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &RedisCommand,
    ) -> Option<std::result::Result<MatchedRedisExchange, CommandMatchDiagnostic>> {
        if command.name != "PUBLISH" {
            return None;
        }
        let mut state = shared.lock().await;
        let scope = RequestAdmission::capture(&state, None, None, None, false);
        if Instant::now() >= self.deadline
            || self.epoch != state.admission_epoch
            || scope.case.as_deref() != Some(&self.case)
            || scope.cancel_reason(&state).is_some()
            || !lane::enabled(&state)
        {
            return None;
        }
        let connection = TargetConnection {
            id: client_id,
            bound: binding.connection(Some(&self.case)),
        };
        let preview = state.redis.match_strict_redis(
            Some(&self.case),
            target,
            connection,
            resp_version,
            database,
            username,
            &command.name,
            &command.args,
        );
        if !matches!(preview, PreferredMatch::Matched(index) if index == self.earlier) {
            return None;
        }
        let mut request = RedisRequest {
            target,
            client_id,
            binding: &mut binding,
            resp_version,
            database,
            username,
            command,
            connection: None,
            started: tokio::time::Instant::now(),
            lane_hint: None,
        };
        let observation = request.observe_once(&mut state);
        let result = request
            .try_select(&mut state, &observation)
            .and_then(|mut matched| {
                if matched.index != self.earlier {
                    state
                        .redis
                        .fail_exchange(&matched, "pipelined Redis predecessor changed".into());
                    return Err(request.interrupted("pipelined Redis predecessor changed"));
                }
                request.on_selected(&mut state, &observation, &mut matched)?;
                Ok(matched)
            });
        if let Err(error) = &result {
            request.on_rejected(&mut state, &observation, error);
        }
        Some(result)
    }
}

fn namespace(exchange: &ReplayExchange) -> Option<String> {
    if exchange.record.response_kind != "integer" || exchange.record.lifecycle_cleanup {
        return None;
    }
    if let Ok(Some(request)) = socketio_rpc::request(&exchange.record.command, &exchange.args) {
        return Some(request.identity.namespace);
    }
    socketio_rpc::broadcast(&exchange.record.command, &exchange.args)
        .ok()
        .flatten()?
        .value["namespace"]
        .as_str()
        .map(str::to_owned)
}
