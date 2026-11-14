//! Ordered fast inputs use exact Case request admission and actual tail delivery.
use super::*;
use crate::interaction::{
    model::{
        DispatchDependency, EndReason, InputAction, InputTranscript, OutputObservation, Protocol,
        TRANSCRIPT_VERSION,
    },
    replay::{
        heartbeat_tail,
        timing::{FastTail, namespace_disconnect, ordered_input},
    },
    socketio::{EngineIoPacket, decode_engine_io_text},
};
use crate::replay::adapters::{DependencyAdapter, ExchangeHandle, resolve_case};

const MAX_REQUESTS: usize = 100_000;
const POLL_MS: u64 = 5;

#[derive(Debug)]
pub(super) struct Source {
    start: DateTime<Utc>,
    cap: u64,
    covered: bool,
    requests: Vec<Request>,
    tail: Option<Tail>,
    passive: Option<heartbeat_tail::Passive>,
}

#[derive(Debug)]
struct Request {
    reference: RecordedReference,
    started_us: u64,
    completed: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SourceOffset {
    ms: u64,
    us: Option<u64>,
}

impl SourceOffset {
    fn earliest_us(self) -> u64 {
        self.us.unwrap_or_else(|| self.ms.saturating_mul(1_000))
    }

    fn latest_us(self) -> u64 {
        self.us
            .unwrap_or_else(|| self.earliest_us().saturating_add(999))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NativeDispatch {
    from: SourceOffset,
    to: SourceOffset,
    first_request: usize,
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
    dispatch_windows: BTreeMap<u64, NativeDispatch>,
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
            tail: Tail::load(path, input, cap).unwrap_or_default(),
            passive: passive_proof(path, input).ok().flatten(),
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
            Some("mysql_exchange" | "redis_exchange" | "http_exchange") => {}
            Some("mysql_connection" | "redis_connection") => return Ok(()),
            Some("redis_pub_sub_push") => {
                // Native pushes own their delivery clock. Only ordinary
                // compressed close timing requires a dependency-only tail.
                self.tail = self
                    .tail
                    .take()
                    .filter(|tail| tail.policy.heartbeat_timeout);
                self.passive = None;
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
        if started < self.start {
            return Ok(());
        }
        let Some(started_us) = (started - self.start)
            .num_microseconds()
            .and_then(|us| u64::try_from(us).ok())
        else {
            return Ok(());
        };
        if self.requests.len() == MAX_REQUESTS {
            self.covered = false;
            return Ok(());
        }
        let completed = time(&event["timestamp"]).and_then(|value| offset(self.start, value));
        self.requests.push(Request {
            reference,
            started_us,
            completed,
        });
        Ok(())
    }

    pub(super) fn resolve(
        mut self,
        state: &mut ReplayState,
        case: &str,
        input: &InputTranscript,
    ) -> Result<Plan> {
        ensure!(
            self.covered,
            "ordered Socket.IO timing needs a complete native request inventory"
        );
        self.requests
            .sort_unstable_by_key(|request| request.started_us);
        let refs = self
            .requests
            .iter()
            .map(|request| request.reference)
            .collect::<Vec<_>>();
        let handles = resolve_case(state, case, &refs, |_, handle| handle)?;
        if let Some(tail) = &mut self.tail
            && !tail.policy.heartbeat_timeout
        {
            for request in self
                .requests
                .iter()
                .take_while(|request| request.started_us / 1_000 < tail.cutoff)
            {
                let Some(completed) = request.completed.filter(|completed| {
                    *completed >= request.started_us / 1_000 && *completed < tail.cutoff
                }) else {
                    // This recording closed while a known request was still in progress.
                    self.tail = None;
                    break;
                };
                tail.quiet_from = tail.quiet_from.max(completed);
            }
        }
        if let Some(passive) = self.passive.take()
            && let Some(setup_finished) = self.requests.iter().try_fold(0, |latest, request| {
                let completed = request.completed?;
                (completed >= request.started_us / 1_000).then_some(latest.max(completed))
            })
            && state
                .protocols
                .redis
                .pubsub
                .native_clock
                .prepare_fast(case, &passive, self.cap, setup_finished)
                .is_some()
        {
            let last_output_ms = passive.outputs.last().expect("proven passive output").0;
            self.tail = Some(Tail {
                policy: FastTail {
                    close_sequence: None,
                    output_count: passive.output_count,
                    idle_ms: 0,
                    heartbeat_timeout: true,
                    native_observation: true,
                },
                cutoff: passive.end_ms,
                quiet_from: last_output_ms,
            });
            tracing::info!(
                case_id = case,
                "enabled ordered fast passive Pub/Sub timing"
            );
        }
        let mut previous = SourceOffset::default();
        let mut dispatch_windows = BTreeMap::new();
        for action in &input.actions {
            let to = SourceOffset {
                ms: action.offset_ms,
                us: action.offset_us,
            };
            if ordered_input(action) || namespace_disconnect(action, input.policy.max_message_bytes)
            {
                let first_request = self
                    .requests
                    .partition_point(|request| request.started_us < previous.earliest_us());
                dispatch_windows.insert(
                    action.sequence,
                    NativeDispatch {
                        from: previous,
                        to,
                        first_request,
                    },
                );
            }
            if input_boundary(action) {
                previous = to;
            }
        }
        Ok(Plan {
            source: self,
            handles,
            dispatch_windows,
        })
    }
}

impl Plan {
    pub(super) fn mysql_candidate_cutoff(
        &self,
        live: &Live,
        anchor: Option<DateTime<Utc>>,
    ) -> Option<DateTime<Utc>> {
        let anchor = self.mysql_anchor_us(live, anchor);
        let cutoff = mysql_candidate_cutoff_us(&live.plan.input.actions, anchor);
        self.mysql_source_time(cutoff)
    }

    pub(super) fn mysql_candidate_anchor(
        &self,
        live: &Live,
        anchor: Option<DateTime<Utc>>,
    ) -> Option<DateTime<Utc>> {
        self.mysql_source_time(self.mysql_anchor_us(live, anchor))
    }

    pub(super) fn mysql_dispatch_prefix(
        &self,
        live: &Live,
    ) -> Option<std::ops::Range<DateTime<Utc>>> {
        let window = live.native_dispatch?;
        Some(
            self.mysql_source_time(window.from.latest_us().saturating_add(1))?
                ..self.mysql_source_time(window.to.earliest_us())?,
        )
    }

    fn mysql_anchor_us(&self, live: &Live, anchor: Option<DateTime<Utc>>) -> u64 {
        anchor
            .and_then(|at| u64::try_from((at - self.source.start).num_microseconds()?).ok())
            .max(live.native_dispatch.map(|window| window.from.earliest_us()))
            .unwrap_or_default()
    }

    fn mysql_source_time(&self, us: u64) -> Option<DateTime<Utc>> {
        self.source
            .start
            .checked_add_signed(chrono::TimeDelta::microseconds(i64::try_from(us).ok()?))
    }

    pub(super) fn tail(&self) -> Option<FastTail> {
        self.source.tail.as_ref().map(|tail| tail.policy.clone())
    }

    pub(super) fn heartbeat_close_at(&self) -> Option<DateTime<Utc>> {
        let tail = self.source.tail.as_ref()?;
        if !tail.policy.heartbeat_timeout {
            return None;
        }
        self.source
            .start
            .checked_add_signed(chrono::TimeDelta::try_milliseconds(
                i64::try_from(tail.cutoff).ok()?,
            )?)
    }

    pub(super) fn native_fast_setup_ready(&self, state: &ReplayState, case: &str) -> bool {
        self.source
            .requests
            .iter()
            .zip(&self.handles)
            .all(|(request, handle)| Self::request_ready(state, case, request, handle, true))
    }

    pub(super) fn native_dispatch_cap(
        &self,
        state: &ReplayState,
        case: &str,
        window: NativeDispatch,
        offset: chrono::TimeDelta,
    ) -> Option<Duration> {
        let us = u64::try_from(offset.num_microseconds()?).ok()?;
        if us <= window.from.latest_us() || us >= window.to.earliest_us() {
            return None;
        }
        // A push can enable the very output that the next input awaits. Its
        // own earlier requests must be admitted independently of that output.
        let to = SourceOffset {
            ms: us / 1_000,
            us: Some(us),
        };
        let (compressible, unadmitted) =
            self.dispatch_prefix(state, case, NativeDispatch { to, ..window });
        (compressible && unadmitted.is_none()).then(|| Duration::from_millis(self.source.cap))
    }

    fn ready(
        &self,
        state: &ReplayState,
        case: &str,
        from: SourceOffset,
        to: SourceOffset,
        tail: bool,
    ) -> bool {
        self.requests_between(from, to).all(|(request, handle)| {
            request.started_us < to.earliest_us()
                && Self::request_ready(state, case, request, handle, tail)
        })
    }

    fn requests_between(
        &self,
        from: SourceOffset,
        to: SourceOffset,
    ) -> impl Iterator<Item = (&Request, &ExchangeHandle)> {
        let first = self
            .source
            .requests
            .partition_point(|entry| entry.started_us < from.earliest_us());
        self.source.requests[first..]
            .iter()
            .zip(&self.handles[first..])
            .take_while(move |(request, _)| request.started_us <= to.latest_us())
    }

    fn request_ready(
        state: &ReplayState,
        case: &str,
        request: &Request,
        handle: &ExchangeHandle,
        tail: bool,
    ) -> bool {
        (match handle.delivery_state(state) {
            Some(ReplayExchangeStatus::Consumed) => true,
            Some(
                ReplayExchangeStatus::Responding | ReplayExchangeStatus::AwaitingClientTermination,
            ) => !tail,
            _ => false,
        }) || dependency_tail::timing_optional(state, case, request.reference)
            || handle.permits_unstarted_omission(state, false, true)
    }

    fn dispatch_prefix(
        &self,
        state: &ReplayState,
        case: &str,
        window: NativeDispatch,
    ) -> (bool, Option<DispatchDependency>) {
        let NativeDispatch {
            from,
            to,
            first_request,
        } = window;
        let input_at = i64::try_from(to.earliest_us()).ok().and_then(|us| {
            self.source
                .start
                .checked_add_signed(chrono::Duration::microseconds(us))
        });
        let mut compressible = true;
        for (request, handle) in self.source.requests[first_request..]
            .iter()
            .zip(&self.handles[first_request..])
            .take_while(|(request, _)| request.started_us <= to.latest_us())
        {
            if request.started_us >= to.earliest_us() {
                // A dependency in a legacy input's millisecond bucket may
                // be produced by that input. It cannot pin the input to its
                // absolute recording time when the proven prefix is ready.
                if to.us.is_some() {
                    compressible = false;
                }
            } else if !Self::request_ready(state, case, request, handle, false) {
                if let ExchangeHandle::Native(DependencyAdapter::Mysql(index)) = *handle
                    && input_at.is_some_and(|at| {
                        state
                            .protocols
                            .mysql
                            .can_defer_autocommit_for_dispatch(index, at)
                    })
                {
                    continue;
                }
                if request.started_us <= from.latest_us() {
                    compressible = false;
                    continue;
                }
                let dependency = match request.reference {
                    RecordedReference::Redis {
                        connection_id,
                        sequence,
                    } => DispatchDependency::Redis {
                        connection_id,
                        sequence,
                    },
                    RecordedReference::Mysql {
                        connection_id,
                        sequence,
                    } => DispatchDependency::Mysql {
                        connection_id,
                        sequence,
                    },
                    RecordedReference::Http { exchange_id } => {
                        DispatchDependency::Http { exchange_id }
                    }
                    _ => unreachable!("ordered fast only plans Redis, MySQL, and HTTP requests"),
                };
                return (false, Some(dependency));
            }
        }
        (compressible, None)
    }
}

pub(super) fn advance(state: &mut ReplayState, tail: bool, query: &Query) -> Result<Value> {
    if let Some(events_ready) = query.events_ready {
        ensure!(!tail, "event readiness is only valid for input dispatch");
        return advance_dispatch(state, query, events_ready);
    }
    let live = state.input_timing.as_ref().expect("validated timeline");
    let plan = live.fast.as_ref().expect("validated fast plan");
    let elapsed = u64::try_from(live.started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if tail
        && plan
            .source
            .tail
            .as_ref()
            .is_some_and(|tail| tail.policy.native_observation)
    {
        let case = live.case.clone();
        let ready = plan.native_fast_setup_ready(state, &case)
            && state
                .protocols
                .redis
                .pubsub
                .native_clock
                .fast_tail_ready(&case, MonoInstant::now());
        return Ok(
            serde_json::json!({"ok":true,"ready":ready,"wait_ms":POLL_MS,
            "advance": Advance::default()}),
        );
    }
    let (sequence, from, to, eligible, ready, idle_tail) = if tail {
        let tail = plan.source.tail.as_ref().context("fast tail unavailable")?;
        let ready = plan.ready(
            state,
            &live.case,
            SourceOffset::default(),
            SourceOffset {
                ms: tail.cutoff,
                us: None,
            },
            true,
        );
        (
            tail.policy.close_sequence.unwrap_or(0),
            tail.quiet_from,
            tail.cutoff,
            true,
            ready,
            tail.policy.close_sequence.is_none(),
        )
    } else {
        let action = input_action(live, query.sequence)?;
        ensure!(
            query.completed.iter().all(|id| action.after.contains(id)),
            "input completion outside original prerequisites"
        );
        let previous = plan
            .dispatch_windows
            .get(&action.sequence)
            .map(|window| window.from);
        let eligible =
            previous.is_some() && action.after.iter().all(|id| query.completed.contains(id));
        let to = SourceOffset {
            ms: action.offset_ms,
            us: action.offset_us,
        };
        let from = previous.unwrap_or(to);
        (
            action.sequence,
            from.ms,
            action.offset_ms,
            eligible,
            eligible && plan.ready(state, &live.case, from, to, false),
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

fn advance_dispatch(state: &mut ReplayState, query: &Query, events_ready: bool) -> Result<Value> {
    let live = state.input_timing.as_ref().expect("validated timeline");
    let plan = live.fast.as_ref().expect("validated fast plan");
    let action = input_action(live, query.sequence)?;
    ensure!(
        query.completed.iter().all(|id| action.after.contains(id))
            && action.after.iter().all(|id| query.completed.contains(id)),
        "dispatch requires all recorded completion identities"
    );
    let window = *plan
        .dispatch_windows
        .get(&action.sequence)
        .context("input outside ordered fast plan")?;
    let (compressible, unadmitted) = plan.dispatch_prefix(state, &live.case, window);
    let NativeDispatch { from, to, .. } = window;
    let cap = plan.source.cap;
    if live.native_dispatch != Some(window) {
        state
            .protocols
            .redis
            .pubsub
            .native_clock
            .plan_dispatch_pace(
                &live.case,
                live.epoch,
                Duration::from_micros(from.latest_us())..Duration::from_micros(to.earliest_us()),
                Duration::from_millis(cap),
            );
    }
    let live = state.input_timing.as_mut().expect("validated timeline");
    let elapsed = u64::try_from(live.started.elapsed().as_millis()).unwrap_or(u64::MAX);
    live.native_dispatch = Some(window);
    let gates_ready = events_ready && unadmitted.is_none();
    if gates_ready && compressible && live.advanced.insert(query.sequence) {
        live.clock.compress(from.ms, to.ms, elapsed, cap);
    }
    let due = if compressible {
        live.clock.effective_ms(to.ms)
    } else {
        to.ms
    };
    let remaining = due.saturating_sub(elapsed);
    let wait_ms = if gates_ready { remaining } else { POLL_MS };
    Ok(serde_json::json!({
        "ok":true,"ready":gates_ready && remaining == 0,
        // An unresolved request in the previous legacy millisecond bucket
        // can become admissible without appearing as a hard dependency.
        "wait_ms":if compressible { wait_ms } else { wait_ms.min(POLL_MS) },
        "unadmitted_request": unadmitted,
        "advance": Advance {removed_ms:live.clock.removed_ms()}
    }))
}

fn input_action(live: &Live, sequence: u64) -> Result<&InputAction> {
    // InputTranscript::validate proves strictly increasing sequence numbers,
    // including transcripts with gaps. Avoid a linear scan under Replay state.
    let actions = &live.plan.input.actions;
    let index = actions
        .binary_search_by_key(&sequence, |action| action.sequence)
        .ok()
        .context("input timing sequence outside original program")?;
    Ok(&actions[index])
}

fn mysql_candidate_cutoff_us(actions: &[InputAction], anchor: u64) -> u64 {
    let start = actions.partition_point(|action| action.offset_ms <= anchor / 1_000);
    let minimum = anchor.saturating_add(3_000_000);
    actions[start..]
        .iter()
        .filter(|action| ordered_input(action))
        .take(3)
        .last()
        .map_or(minimum, |action| {
            let offset = SourceOffset {
                ms: action.offset_ms,
                us: action.offset_us,
            };
            minimum.max(offset.latest_us())
        })
}

fn input_boundary(action: &InputAction) -> bool {
    use crate::interaction::model::{InputActionKind, MessageKind};
    !matches!(&action.action, InputActionKind::Message { message }
    if message.kind == MessageKind::Text && matches!(
        decode_engine_io_text(&message.data, usize::MAX),
        Ok(EngineIoPacket::Ping(_) | EngineIoPacket::Pong(_))))
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
            heartbeat_tail::timeout(input, &response.interaction)
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
            EndReason::ServerEof if let Some((eof, _)) = heartbeat => (eof, None, last_input),
            _ => return Ok(None),
        };
        if heartbeat.is_none()
            && completion
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
        let tail = (heartbeat.is_some() || quiet_from < cutoff).then(|| Self {
            policy: FastTail {
                close_sequence,
                output_count: outputs.count(),
                idle_ms: cap.min(cutoff.saturating_sub(quiet_from)),
                heartbeat_timeout: heartbeat.is_some(),
                native_observation: false,
            },
            cutoff,
            quiet_from,
        });
        Ok(tail)
    }
}

fn passive_proof(path: &Path, input: &InputTranscript) -> Result<Option<heartbeat_tail::Passive>> {
    if input.socket_io_heartbeat.is_none()
        || heartbeat_tail::Passive::input_namespace(input).is_none()
    {
        return Ok(None);
    }
    #[derive(Deserialize)]
    struct Response {
        interaction: OutputObservation,
    }
    let file = std::fs::File::open(path.join("expected-response.json"))?;
    let response: Response = serde_json::from_reader(std::io::BufReader::new(file))?;
    Ok(heartbeat_tail::Passive::recognize(
        input,
        &response.interaction,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interaction::{model::WireMessage, observation::Observation};

    #[test]
    fn mysql_window_covers_three_source_events_and_at_least_three_seconds() {
        let inputs = |offsets: [u64; 3]| {
            offsets
                .into_iter()
                .enumerate()
                .map(|(index, offset_ms)| {
                    serde_json::from_value::<InputAction>(serde_json::json!({
                        "sequence": index + 1,
                        "offset_ms": offset_ms,
                        "action": {"kind":"message","message":{"kind":"text","data":"42[\"event\"]"}}
                    }))
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            mysql_candidate_cutoff_us(&inputs([527, 527, 527]), 451_412),
            3_451_412
        );
        assert_eq!(
            mysql_candidate_cutoff_us(&inputs([527, 4_000, 7_000]), 451_412),
            7_000_999
        );
        assert_eq!(
            mysql_candidate_cutoff_us(&inputs([527, 4_000, 7_000]), 527_000),
            7_000_999
        );
        assert_eq!(
            mysql_candidate_cutoff_us(&inputs([527, 527, 527]), 9_000_000),
            12_000_000
        );
    }

    #[test]
    fn clean_source_heartbeat_timeout_enables_the_terminal_phase() {
        let mut observed = Observation::new(Protocol::SocketIo, Default::default()).unwrap();
        observed
            .output(
                WireMessage::text(r#"0{"sid":"s","pingInterval":25,"pingTimeout":20}"#),
                0,
            )
            .unwrap();
        observed.output(WireMessage::text("2"), 25).unwrap();
        observed.server_close(Some(1000), String::new());
        let (input, output) = observed.finish(EndReason::ServerEof, 71, true).unwrap();
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("expected-response.json"),
            serde_json::json!({
                "timestamp": "2026-11-07T00:00:00.201Z",
                "duration_ms": 171,
                "interaction": output,
            })
            .to_string(),
        )
        .unwrap();
        let tail = Tail::load(directory.path(), &input, 5).unwrap().unwrap();
        assert_eq!(tail.cutoff, 71);
        assert!(tail.policy.heartbeat_timeout);
    }
}
