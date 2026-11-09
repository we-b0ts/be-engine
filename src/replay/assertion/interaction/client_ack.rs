//! Correlate independent native replies without changing business event order.
use super::*;
use crate::interaction::{
    model::{InputActionKind, InputTranscript},
    socketio::{EngineIoPacket, SocketIoKind, decode_engine_io_text},
};
use std::collections::{BTreeSet, HashMap};

mod mixed;

type Key = (String, u64);
const MAX_ACTIONS: usize = 16_384;
const MAX_EDGES: usize = 65_536;

/// Original request identities, completion edges and input fences.
pub(in crate::replay::assertion) struct Context {
    requests: BTreeMap<Key, Option<Request>>,
    graph: Vec<(u64, Vec<u64>, bool)>,
    control_offsets: Vec<u64>,
    first_completion_uses: HashMap<u64, u64>,
}

#[derive(Clone, Copy)]
struct Request {
    sequence: u64,
    offset_ms: u64,
}

impl Context {
    pub(in crate::replay::assertion) fn prepare(
        input: Option<&InputTranscript>,
    ) -> Result<Option<Self>> {
        let Some(input) = input.filter(|input| {
            input.protocol == Protocol::SocketIo && !input.policy.preserve_input_timing
        }) else {
            return Ok(None);
        };
        input.validate()?;
        // Large or legacy ambiguous programs retain strict positional comparison.
        if input.actions.len() > MAX_ACTIONS
            || input
                .actions
                .iter()
                .map(|action| action.after.len())
                .sum::<usize>()
                > MAX_EDGES
        {
            return Ok(None);
        }
        let mut requests = BTreeMap::new();
        let mut graph = Vec::with_capacity(input.actions.len());
        let mut control_offsets = Vec::new();
        let mut first_completion_uses = HashMap::new();
        for action in &input.actions {
            for &prior in &action.after {
                first_completion_uses
                    .entry(prior)
                    .or_insert(action.offset_ms);
            }
            let InputActionKind::Message { message } = &action.action else {
                graph.push((action.sequence, action.after.clone(), true));
                control_offsets.push(action.offset_ms);
                continue;
            };
            if message.kind != MessageKind::Text {
                graph.push((action.sequence, action.after.clone(), true));
                control_offsets.push(action.offset_ms);
                continue;
            }
            let frame = decode_engine_io_text(&message.data, input.policy.max_message_bytes);
            let control = !matches!(&frame, Ok(EngineIoPacket::Message(packet))
                if matches!(packet.kind, SocketIoKind::Event | SocketIoKind::BinaryEvent | SocketIoKind::Ack | SocketIoKind::BinaryAck))
                && !matches!(
                    &frame,
                    Ok(EngineIoPacket::Ping(_) | EngineIoPacket::Pong(_))
                );
            graph.push((action.sequence, action.after.clone(), control));
            if control {
                control_offsets.push(action.offset_ms);
            }
            let Ok(EngineIoPacket::Message(packet)) = frame else {
                continue;
            };
            if !matches!(packet.kind, SocketIoKind::Event | SocketIoKind::BinaryEvent) {
                continue;
            }
            if let Some(id) = packet.id {
                // Reused IDs cannot identify a unique original request occurrence.
                requests
                    .entry((packet.namespace, id))
                    .and_modify(|sequence| *sequence = None)
                    .or_insert(Some(Request {
                        sequence: action.sequence,
                        offset_ms: action.offset_ms,
                    }));
            }
        }
        Ok(Some(Self {
            requests,
            graph,
            control_offsets,
            first_completion_uses,
        }))
    }

    fn independent(&self, keys: &[&Key]) -> bool {
        let Some(sequences) = keys
            .iter()
            .map(|key| self.request(key).map(|request| request.sequence))
            .collect::<Option<BTreeSet<_>>>()
        else {
            return false;
        };
        if sequences.len() != keys.len() {
            return false;
        }
        if self.graph.iter().any(|(sequence, _, control)| {
            *control
                && sequences.first().is_some_and(|first| sequence > first)
                && sequences.last().is_some_and(|last| sequence < last)
        }) {
            return false;
        }
        // Propagate whether an explicit completion path reaches any request in
        // this run. Common predecessors do not order sibling requests.
        let mut dependent = HashMap::<u64, bool>::new();
        for (sequence, after, _) in &self.graph {
            let follows = after
                .iter()
                .any(|prior| dependent.get(prior) == Some(&true));
            if follows && sequences.contains(sequence) {
                return false;
            }
            dependent.insert(*sequence, follows || sequences.contains(sequence));
        }
        true
    }

    fn request(&self, key: &Key) -> Option<Request> {
        self.requests.get(key).copied().flatten()
    }

    pub(super) fn alignment(
        &self,
        source: &[WireMessage],
        target: &[WireMessage],
        source_offsets: &[u64],
    ) -> Vec<usize> {
        let mut alignment = (0..target.len()).collect::<Vec<_>>();
        if source == target {
            return alignment;
        }
        let mut source = source.iter().map(Frame::parse).collect::<Vec<_>>();
        let mut target = target.iter().map(Frame::parse).collect::<Vec<_>>();
        // Compare a reused request ID at its original position, while letting
        // each side prove its own ACK-only or mixed reordering independently.
        for (source, target) in source.iter_mut().zip(&mut target) {
            if source.ack().is_some_and(|key| {
                self.requests.get(key).is_some_and(Option::is_none) && target.ack() == Some(key)
            }) {
                *source = Frame::Fence;
                *target = Frame::Fence;
            }
        }
        let mixed_runs = self.align_mixed_runs(&source, &target, source_offsets, &mut alignment);
        let mut mixed_runs = mixed_runs.into_iter().peekable();
        let mut start = 0;
        while start < source.len() {
            if mixed_runs.peek().is_some_and(|run| run.start == start) {
                start = mixed_runs.next().expect("aligned run").end;
                continue;
            }
            if source[start].ack().is_none() {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < source.len() && source[end].ack().is_some() {
                end += 1;
            }
            if end - start > 1 && end <= target.len() {
                self.align_ack_run(&source, &target, start..end, &mut alignment);
            }
            start = end;
        }
        alignment
    }

    fn align_ack_run(
        &self,
        source: &[Frame],
        target: &[Frame],
        run: std::ops::Range<usize>,
        alignment: &mut [usize],
    ) {
        let keys = source[run.clone()]
            .iter()
            .map(Frame::ack)
            .collect::<Option<Vec<_>>>()
            .expect("ACK run");
        if !self.independent(&keys) {
            return;
        }
        let mut actual = BTreeMap::new();
        for index in run.clone() {
            let Some(key) = target[index].ack() else {
                return;
            };
            if actual.insert(key, index).is_some() {
                return;
            }
        }
        let Some(indices) = keys
            .iter()
            .map(|key| actual.get(key).copied())
            .collect::<Option<Vec<_>>>()
        else {
            return;
        };
        // Equal sizes and unique exact keys rule out missing/extra/unknown ACKs.
        if actual.len() == keys.len() {
            alignment[run].copy_from_slice(&indices);
        }
    }
}

enum Frame {
    Ack(Key),
    Business(String),
    Fence,
}

impl Frame {
    fn parse(message: &WireMessage) -> Self {
        if message.kind != MessageKind::Text
            || !message.data.starts_with("42") && !message.data.starts_with("43")
        {
            return Self::Fence;
        }
        let Ok(EngineIoPacket::Message(packet)) = decode_engine_io_text(&message.data, usize::MAX)
        else {
            return Self::Fence;
        };
        if packet.attachments != 0 || !packet.binary.is_empty() {
            return Self::Fence;
        }
        match (packet.kind, packet.id) {
            (SocketIoKind::Ack, Some(id)) => Self::Ack((packet.namespace, id)),
            (SocketIoKind::Event, _) => Self::Business(packet.namespace),
            _ => Self::Fence,
        }
    }

    fn ack(&self) -> Option<&Key> {
        match self {
            Self::Ack(key) => Some(key),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
