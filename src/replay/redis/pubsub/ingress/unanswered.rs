//! A live Source session and its local publisher distinguish foreign RPC inputs.
use super::*;
use std::ops::Range;

#[derive(PartialEq, Eq, Hash)]
struct RoomKey {
    endpoint: TargetKey,
    channel: Vec<u8>,
    namespace: String,
    sid: String,
}

impl RoomKey {
    fn new(endpoint: &TargetKey, channel: &[u8], identity: &rpc::Identity) -> Self {
        Self {
            endpoint: endpoint.clone(),
            channel: channel.to_vec(),
            namespace: identity.namespace.clone(),
            sid: identity.sid.clone(),
        }
    }
}

pub(super) struct Room<'a> {
    pub(super) case: &'a str,
    pub(super) window: &'a Range<DateTime<Utc>>,
    local_hosts: HashSet<String>,
    first_publish: DateTime<Utc>,
}

#[derive(Default)]
pub(super) struct Rooms<'a>(HashMap<RoomKey, Option<Room<'a>>>);

impl<'a> Rooms<'a> {
    pub(super) fn prepare(
        exchanges: &'a [ReplayExchange],
        sessions: &'a namespace_sessions::NamespaceSessions,
    ) -> Self {
        let mut rooms = Self::default();
        for exchange in exchanges {
            if exchange.source != ReplaySource::Case
                || exchange.shared_rule_id.is_some()
                || !exchange.record.replay_safe
                || exchange.record.outcome != DependencyExchangeOutcome::Response
                || exchange.record.response_kind != "integer"
            {
                continue;
            }
            let Some(case) = exchange.case_id.as_deref() else {
                continue;
            };
            let Ok(Some(request)) = rpc::request(&exchange.record.command, &exchange.args) else {
                continue;
            };
            let identity = request.identity;
            let Some(window) = sessions.source_window(case, &identity.namespace, &identity.sid)
            else {
                continue;
            };
            let Some(timestamp) = exchange
                .record
                .started_at()
                .filter(|at| window.contains(at))
            else {
                continue;
            };
            let endpoint = TargetKey {
                host: normalize_host(&exchange.record.target_host),
                port: exchange.record.target_port,
            };
            let room = rooms
                .0
                .entry(RoomKey::new(&endpoint, &exchange.args[0], &identity))
                .or_insert_with(|| {
                    Some(Room {
                        case,
                        window,
                        local_hosts: HashSet::new(),
                        first_publish: timestamp,
                    })
                });
            if let Some(owner) = room {
                if owner.case != case {
                    *room = None;
                } else {
                    owner.first_publish = owner.first_publish.min(timestamp);
                    owner.local_hosts.insert(identity.host);
                }
            }
        }
        rooms
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn find(
        &self,
        key: &Key,
        at: Option<DateTime<Utc>>,
        source: ReplaySource,
    ) -> Option<&Room<'a>> {
        if source != ReplaySource::Process {
            return None;
        }
        let at = at?;
        let room = self
            .0
            .get(&RoomKey::new(&key.0, &key.1, &key.2))?
            .as_ref()?;
        (at > room.first_publish
            && room.window.contains(&at)
            && !room.local_hosts.contains(&key.2.host))
        .then_some(room)
    }
}
