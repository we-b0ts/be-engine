//! Admission proofs for reordered Socket.IO publishes on one Redis stream.
use super::*;
use crate::redis::socketio_rpc;
use tokio::time::Instant;
mod close_tail;
pub(in crate::replay::redis) use close_tail::BroadcastWindow;
#[cfg(test)]
mod tests;

/// Sequential pairs of room broadcasts can share a RESP stream with an
/// independent call. Each pair's second publish awaits the first reply.
#[derive(Debug)]
pub(in crate::replay::redis) struct SerialPublish {
    pub(in crate::replay::redis) index: usize,
    pub(in crate::replay::redis) predecessors: Arc<[usize]>,
    pub(in crate::replay::redis) first_blocker: usize,
    pub(in crate::replay::redis) broadcast: Option<BroadcastWindow>,
}

impl SerialPublish {
    pub(super) fn from_blocker(
        state: &ReplayState,
        case: &str,
        error: &CommandMatchDiagnostic,
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
            || candidate.connection_id != blocked_by.connection_id
        {
            return None;
        }
        let index = lane::ordinary_slot(&state.redis, case, candidate)?;
        let first = lane::ordinary_slot(&state.redis, case, blocked_by)?;
        if let Some(broadcast) = close_tail::prove(state, case, first, index) {
            return Some(broadcast);
        }
        // An attribution overlay can move other cases' traffic away from the
        // physical connection without renumbering the remaining Source slots.
        let predecessors = state.redis.candidates.lane_prefix(first, index, 4)?;
        if !matches!(predecessors.len(), 2 | 4) {
            return None;
        }
        let later = &state.redis.exchanges[index];
        if predecessors
            .iter()
            .chain(std::iter::once(&index))
            .map(|&index| &state.redis.exchanges[index])
            .any(|exchange| {
                exchange.record.command != "PUBLISH"
                    || !lane::is_ordinary(exchange)
                    || state.redis.connection_scopes.is_stateful(exchange)
                    || !exchange.status.is_available()
                    || exchange.record.response_kind != "integer"
                    || exchange.record.lifecycle_cleanup
                    || exchange.args.first() != later.args.first()
            })
        {
            return None;
        }
        let call = socketio_rpc::request("PUBLISH", &later.args).ok()??;
        let mut pairs = predecessors.chunks_exact(2).map(|pair| {
            room_broadcast_pair(
                &state.redis.exchanges[pair[0]],
                &state.redis.exchanges[pair[1]],
            )
        });
        let first_pair = pairs.next()??;
        if first_pair.2["namespace"] == call.identity.namespace
            || pairs.any(|pair| pair.as_ref() != Some(&first_pair))
        {
            return None;
        }
        Some(Self {
            index,
            predecessors: predecessors.into(),
            first_blocker: first,
            broadcast: None,
        })
    }
}

fn room_broadcast_pair(
    first: &ReplayExchange,
    second: &ReplayExchange,
) -> Option<(String, String, serde_json::Value)> {
    let mut first_message = socketio_rpc::broadcast("PUBLISH", &first.args).ok()??.value;
    let mut second_message = socketio_rpc::broadcast("PUBLISH", &second.args)
        .ok()??
        .value;
    let first_room = first_message.as_object_mut()?.remove("room")?;
    let second_room = second_message.as_object_mut()?.remove("room")?;
    let first_room = first_room.as_str()?;
    let second_room = second_room.as_str()?;
    if first_room.is_empty()
        || second_room.is_empty()
        || first_room == second_room
        || first_message != second_message
    {
        return None;
    }
    // Within each pair the payload must be identical. Repeated broadcasts to
    // the same two rooms may report a different value on the next occurrence.
    first_message.as_object_mut()?.remove("data")?;
    Some((first_room.into(), second_room.into(), first_message))
}

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
        if matches!(route, AdapterRoute::Callback(_))
            && !state.redis.pubsub.is_adapter_source(first)
        {
            return None;
        }
        (first.args.first() == second.args.first() && route.can_precede(&later_route)).then(|| {
            Self {
                epoch: state.admission_epoch,
                deadline,
                case: case.to_owned(),
                earlier,
                later,
                route,
            }
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
        if !self
            .route
            .accepts(&AdapterRoute::from_args(&command.name, &command.args)?)
        {
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

#[derive(Debug)]
enum AdapterRoute {
    Emit {
        namespace: String,
        event: String,
        rpc: Option<socketio_rpc::Identity>,
    },
    Callback(socketio_rpc::Identity),
}

impl AdapterRoute {
    fn from_args(command: &str, args: &[Vec<u8>]) -> Option<Self> {
        if let Ok(Some(request)) = socketio_rpc::request(command, args) {
            return Some(Self::Emit {
                namespace: request.identity.namespace.clone(),
                event: request.value["event"].as_str()?.into(),
                rpc: Some(request.identity),
            });
        }
        if let Ok(Some(broadcast)) = socketio_rpc::broadcast(command, args) {
            return Some(Self::Emit {
                namespace: broadcast.value["namespace"].as_str()?.into(),
                event: broadcast.value["event"].as_str()?.into(),
                rpc: None,
            });
        }
        let [_, payload] = args else {
            return None;
        };
        if command != "PUBLISH" {
            return None;
        }
        let (identity, _) = socketio_rpc::callback(payload).ok().flatten()?;
        Some(Self::Callback(identity))
    }

    fn can_precede(&self, later: &Self) -> bool {
        match (self, later) {
            (
                Self::Emit { namespace, .. },
                Self::Emit {
                    namespace: later_namespace,
                    ..
                },
            ) => namespace != later_namespace,
            (
                Self::Callback(earlier),
                Self::Emit {
                    rpc: Some(later), ..
                },
            ) => {
                // The remote callback and local call address the same live
                // namespace session, with different originating managers.
                earlier.namespace == later.namespace
                    && earlier.sid == later.sid
                    && earlier.host != later.host
            }
            _ => false,
        }
    }

    fn accepts(&self, actual: &Self) -> bool {
        match (self, actual) {
            (
                Self::Emit {
                    namespace,
                    event,
                    rpc,
                },
                Self::Emit {
                    namespace: actual_namespace,
                    event: actual_event,
                    rpc: actual_rpc,
                },
            ) => {
                namespace == actual_namespace
                    && event == actual_event
                    && rpc.is_some() == actual_rpc.is_some()
            }
            (Self::Callback(source), Self::Callback(actual)) => {
                // The normal exact-slot matcher validates the mapped SID and payload.
                source.host == actual.host
                    && source.namespace == actual.namespace
                    && source.id == actual.id
            }
            _ => false,
        }
    }
}
