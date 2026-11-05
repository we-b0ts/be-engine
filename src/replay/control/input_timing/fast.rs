//! Ordered fast inputs use exact Case request admission and actual tail delivery.
use super::*;
use crate::interaction::{
    model::{
        EndReason, InputAction, InputTranscript, OutputObservation, Protocol, TRANSCRIPT_VERSION,
    },
    replay::{heartbeat_tail, timing::FastTail},
    socketio::{EngineIoPacket, SocketIoKind, decode_engine_io_text},
};
use crate::replay::adapters::{ExchangeHandle, resolve_case};

const MAX_REQUESTS: usize = 100_000;
const POLL_MS: u64 = 5;

#[derive(Debug)]
pub(super) struct Source {
    start: DateTime<Utc>,
    cap: u64,
    covered: bool,
    requests: Vec<Request>,
    tail: Option<Tail>,
}

#[derive(Debug)]
struct Request {
    reference: RecordedReference,
    started: u64,
    completed: Option<u64>,
}

#[derive(Debug)]
struct Tail {
    policy: FastTail,
    cutoff: u64,
    quiet_from: u64,
}

#[derive(Debug)]
pub(super) struct Plan {
    source: Source,
    handles: Vec<ExchangeHandle>,
    previous_input: BTreeMap<u64, u64>,
}

impl Source {
    pub(super) fn new(
        path: &Path,
        input: &InputTranscript,
        cap: u64,
        start: DateTime<Utc>,
    ) -> Self {
        Self {
            start,
            cap,
            covered: true,
            requests: Vec::new(),
            tail: Tail::load(path, input, cap).ok().flatten(),
        }
    }

    pub(super) fn record(&mut self, raw: &[u8]) -> Result<()> {
        if !self.covered {
            return Ok(());
        }
        let event: Value = serde_json::from_slice(raw)?;
        if event["capture"]["semantic_required"] == false {
            return Ok(());
        }
        match event["event_type"].as_str() {
            Some("mysql_exchange" | "redis_exchange") => {}
            Some("mysql_connection" | "redis_connection") => return Ok(()),
            Some("redis_pub_sub_push") => {
                self.tail = None;
                return Ok(());
            }
            _ => {
                self.covered = false;
                return Ok(());
            }
        }
        let reference = match dependency_tail::recorded_reference(&event) {
            Ok(Some(reference)) => reference,
            Ok(None) => return Ok(()),
            Err(_) => {
                self.covered = false;
                return Ok(());
            }
        };
        let Some(started) = time(&event["request_started_at"]) else {
            self.covered = false;
            return Ok(());
        };
        let Some(started) = offset(self.start, started) else {
            return Ok(());
        };
        if self.requests.len() == MAX_REQUESTS {
            self.covered = false;
            return Ok(());
        }
        let completed = time(&event["timestamp"]).and_then(|value| offset(self.start, value));
        self.requests.push(Request {
            reference,
            started,
            completed,
        });
        Ok(())
    }

    pub(super) fn resolve(
        mut self,
        state: &ReplayState,
        case: &str,
        input: &InputTranscript,
    ) -> Result<Plan> {
        ensure!(
            self.covered,
            "ordered Socket.IO timing needs a complete native request inventory"
        );
        self.requests
            .sort_unstable_by_key(|request| request.started);
        let refs = self
            .requests
            .iter()
            .map(|request| request.reference)
            .collect::<Vec<_>>();
        let handles = resolve_case(state, case, &refs, |_, handle| handle)?;
        if self.tail.as_ref().is_some_and(|tail| {
            tail.policy.heartbeat_acks.is_some()
                && self
                    .requests
                    .last()
                    .is_some_and(|request| request.started >= tail.cutoff)
        }) {
            self.tail = None;
        }
        if let Some(tail) = &mut self.tail {
            for request in self
                .requests
                .iter()
                .take_while(|request| request.started < tail.cutoff)
            {
                let Some(completed) = request
                    .completed
                    .filter(|completed| *completed >= request.started && *completed < tail.cutoff)
                else {
                    // This recording closed while a known request was still in progress.
                    self.tail = None;
                    break;
                };
                tail.quiet_from = tail.quiet_from.max(completed);
            }
        }
        ensure!(
            input
                .socket_io_heartbeat
                .as_ref()
                .is_none_or(|program| !program.responses.is_empty())
                || self
                    .tail
                    .as_ref()
                    .is_some_and(|tail| tail.policy.heartbeat_acks.is_some()),
            "ordered timing for an unanswered heartbeat requires an eligible heartbeat tail"
        );
        let mut previous = 0;
        let mut previous_input = BTreeMap::new();
        for action in &input.actions {
            if delivery_prefix(action) {
                previous_input.insert(action.sequence, previous);
            }
            if input_boundary(action) {
                previous = action.offset_ms;
            }
        }
        Ok(Plan {
            source: self,
            handles,
            previous_input,
        })
    }
}

impl Plan {
    pub(super) fn tail(&self) -> Option<FastTail> {
        self.source.tail.as_ref().map(|tail| tail.policy.clone())
    }

    fn ready(&self, state: &ReplayState, case: &str, from: u64, to: u64, tail: bool) -> bool {
        let first = self
            .source
            .requests
            .partition_point(|entry| entry.started < from);
        self.source.requests[first..]
            .iter()
            .zip(&self.handles[first..])
            .take_while(|(request, _)| request.started <= to)
            .all(|(request, handle)| {
                request.started < to
                    && (match handle.delivery_state(state) {
                        Some(ReplayExchangeStatus::Consumed) => true,
                        Some(
                            ReplayExchangeStatus::Responding
                            | ReplayExchangeStatus::AwaitingClientTermination,
                        ) => !tail,
                        _ => false,
                    } || dependency_tail::timing_optional(state, case, request.reference)
                        || handle.permits_unstarted_omission(state, false, true))
            })
    }
}

pub(super) fn advance(state: &mut ReplayState, tail: bool, query: &Query) -> Result<Value> {
    let live = state.input_timing.as_ref().expect("validated timeline");
    let plan = live.fast.as_ref().expect("validated fast plan");
    let elapsed = u64::try_from(live.started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (sequence, from, to, eligible, ready, idle_tail) = if tail {
        let tail = plan.source.tail.as_ref().context("fast tail unavailable")?;
        let ready = if tail.policy.heartbeat_acks.is_some() {
            // Native omission proof can settle an unstarted setup/cleanup
            // exchange. An ordinary dependency must finish on the wire.
            plan.handles.iter().all(|handle| {
                handle.delivery_state(state) == Some(ReplayExchangeStatus::Consumed)
                    || handle.permits_unstarted_omission(state, false, true)
            })
        } else {
            plan.ready(state, &live.case, 0, tail.cutoff, true)
        };
        (
            tail.policy.close_sequence.unwrap_or(0),
            tail.quiet_from,
            tail.cutoff,
            true,
            ready,
            tail.policy.close_sequence.is_none(),
        )
    } else {
        let action = live
            .plan
            .input
            .actions
            .iter()
            .find(|action| action.sequence == query.sequence)
            .context("input timing sequence outside original program")?;
        ensure!(
            query.completed.iter().all(|id| action.after.contains(id)),
            "input completion outside original prerequisites"
        );
        let previous = plan.previous_input.get(&action.sequence).copied();
        let eligible =
            previous.is_some() && action.after.iter().all(|id| query.completed.contains(id));
        let from = previous.unwrap_or(action.offset_ms);
        (
            action.sequence,
            from,
            action.offset_ms,
            eligible,
            eligible && plan.ready(state, &live.case, from, action.offset_ms, false),
            false,
        )
    };
    let live = state.input_timing.as_mut().expect("validated timeline");
    if eligible && ready && !idle_tail && live.advanced.insert(sequence) {
        let cap = live.fast.as_ref().expect("validated fast plan").source.cap;
        live.clock.compress(from, to, elapsed, cap);
    }
    // Missing request admission prevents early sending, but never extends the
    // original input deadline, even after earlier gaps were shortened.
    let deadline = if eligible && !ready {
        to
    } else {
        live.clock.effective_ms(to)
    };
    let remaining = deadline.saturating_sub(elapsed);
    let (ready, wait_ms) = if idle_tail {
        (ready, POLL_MS)
    } else if eligible && !ready {
        (remaining == 0, remaining.min(POLL_MS))
    } else {
        (remaining == 0, remaining)
    };
    Ok(
        serde_json::json!({"ok":true,"ready":ready,"wait_ms":wait_ms,
        "advance": Advance {removed_ms:live.clock.removed_ms()}}),
    )
}

fn input_boundary(action: &InputAction) -> bool {
    use crate::interaction::model::{InputActionKind, MessageKind};
    !matches!(&action.action, InputActionKind::Message { message }
    if message.kind == MessageKind::Text && matches!(
        decode_engine_io_text(&message.data, usize::MAX),
        Ok(EngineIoPacket::Ping(_) | EngineIoPacket::Pong(_))
            | Ok(EngineIoPacket::Message(crate::interaction::socketio::SocketIoPacket {
                kind: SocketIoKind::Ack | SocketIoKind::BinaryAck, ..
            }))))
}

fn time(value: &Value) -> Option<DateTime<Utc>> {
    value.as_str()?.parse().ok()
}

fn offset(start: DateTime<Utc>, at: DateTime<Utc>) -> Option<u64> {
    (at >= start).then(|| (at - start).num_milliseconds() as u64)
}

impl Tail {
    fn load(path: &Path, input: &InputTranscript, cap: u64) -> Result<Option<Self>> {
        use std::io::{BufReader, Seek};

        #[derive(Deserialize)]
        struct Response {
            interaction: Option<Completion>,
        }
        #[derive(Deserialize)]
        struct Completion {
            version: u8,
            protocol: Protocol,
            end: End,
            events: Vec<OutputClock>,
        }
        #[derive(Deserialize)]
        struct OutputClock {
            offset_ms: u64,
            #[serde(default)]
            heartbeat: bool,
        }
        #[derive(Deserialize)]
        struct End {
            reason: EndReason,
            clean: bool,
            offset_ms: u64,
            pending: Vec<u64>,
            partial_message: Option<serde::de::IgnoredAny>,
        }
        let Ok(file) = std::fs::File::open(path.join("expected-response.json")) else {
            return Ok(None);
        };
        // Ordinary tails need only clocks and counts. Decode protocol frames
        // only to classify a clean server EOF, without retaining their payloads.
        let mut reader = BufReader::new(file);
        let response: Response = serde_json::from_reader(&mut reader)?;
        let Some(completion) = response.interaction.filter(|completion| {
            completion.version == TRANSCRIPT_VERSION
                && completion.protocol == Protocol::SocketIo
                && completion.end.clean
                && completion.end.partial_message.is_none()
        }) else {
            return Ok(None);
        };
        let heartbeat = if completion.end.reason == EndReason::ServerEof {
            #[derive(Deserialize)]
            struct WireResponse {
                interaction: OutputObservation,
            }
            reader.rewind()?;
            let response: WireResponse = serde_json::from_reader(reader)?;
            heartbeat_tail::recognize(input, &response.interaction)
        } else {
            None
        };
        if heartbeat.is_none() && !completion.end.pending.is_empty() {
            return Ok(None);
        }
        let last_input = input.actions.last().map_or(0, |action| action.offset_ms);
        let (cutoff, close_sequence, last_input) = match completion.end.reason {
            EndReason::BusinessIdle => (completion.end.offset_ms, None, last_input),
            EndReason::ClientClose => {
                let Some(close) = input
                    .actions
                    .iter()
                    .rev()
                    .take_while(|action| cancellation(action))
                    .last()
                else {
                    return Ok(None);
                };
                let last = input
                    .actions
                    .iter()
                    .take_while(|action| action.sequence < close.sequence)
                    .last()
                    .map_or(0, |action| action.offset_ms);
                (close.offset_ms, Some(close.sequence), last)
            }
            EndReason::ServerEof if let Some(evidence) = &heartbeat => {
                (evidence.last_ping_ms, None, last_input)
            }
            _ => return Ok(None),
        };
        if completion
            .events
            .iter()
            .any(|event| !event.heartbeat && event.offset_ms == cutoff)
        {
            return Ok(None);
        }
        let outputs = completion
            .events
            .iter()
            .filter(|event| !event.heartbeat && event.offset_ms < cutoff);
        let quiet_from = outputs
            .clone()
            .map(|event| event.offset_ms)
            .max()
            .unwrap_or(0)
            .max(last_input);
        Ok((quiet_from < cutoff).then(|| Self {
            policy: FastTail {
                close_sequence,
                output_count: outputs.count(),
                idle_ms: cap.min(cutoff.saturating_sub(quiet_from)),
                heartbeat_acks: heartbeat.map(|evidence| evidence.acknowledged),
            },
            cutoff,
            quiet_from,
        }))
    }
}
