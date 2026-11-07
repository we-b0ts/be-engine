//! Proof for reading one adjacent Socket.IO publish from a blocked Redis stream.
use super::*;
use crate::redis::socketio_rpc;
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
    route: AdapterRoute,
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
        let route = recorded_route(first)?;
        let later_route = recorded_route(second)?;
        (first.args.first() == second.args.first() && route.namespace != later_route.namespace)
            .then(|| Self {
                epoch: state.admission_epoch,
                deadline,
                case: case.to_owned(),
                earlier,
                later,
                route,
            })
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
        if AdapterRoute::from_args(&command.name, &command.args)? != self.route {
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
        let earlier = state.redis.exchanges.get(self.earlier)?;
        if !earlier.status.is_available() || earlier.args.first() != command.args.first() {
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
            expected_index: Some(self.earlier),
        };
        let observation = request.observe_once(&mut state);
        let result = request
            .try_select(&mut state, &observation)
            .and_then(|mut matched| {
                request.on_selected(&mut state, &observation, &mut matched)?;
                Ok(matched)
            });
        if let Err(error) = &result {
            request.on_rejected(&mut state, &observation, error);
        }
        Some(result)
    }
}

fn recorded_route(exchange: &ReplayExchange) -> Option<AdapterRoute> {
    if exchange.record.response_kind != "integer" || exchange.record.lifecycle_cleanup {
        return None;
    }
    AdapterRoute::from_args(&exchange.record.command, &exchange.args)
}

#[derive(Debug, PartialEq, Eq)]
struct AdapterRoute {
    namespace: String,
    event: String,
    rpc: bool,
}

impl AdapterRoute {
    fn from_args(command: &str, args: &[Vec<u8>]) -> Option<Self> {
        if let Ok(Some(request)) = socketio_rpc::request(command, args) {
            return Some(Self {
                namespace: request.identity.namespace,
                event: request.value["event"].as_str()?.into(),
                rpc: true,
            });
        }
        let broadcast = socketio_rpc::broadcast(command, args).ok().flatten()?;
        Some(Self {
            namespace: broadcast.value["namespace"].as_str()?.into(),
            event: broadcast.value["event"].as_str()?.into(),
            rpc: false,
        })
    }
}
