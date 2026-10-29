//! Correlate independent native replies without changing business event order.
use super::*;
use crate::interaction::{
    model::{InputActionKind, InputTranscript},
    socketio::{EngineIoPacket, SocketIoKind, decode_engine_io_text},
};
use std::collections::{BTreeSet, HashMap};

type Key = (String, u64);
const MAX_ACTIONS: usize = 16_384;
const MAX_EDGES: usize = 65_536;

/// Only original request identities and completion edges survive preparation.
pub(in crate::replay::assertion) struct Context {
    requests: BTreeMap<Key, Option<u64>>,
    graph: Vec<(u64, Vec<u64>, bool)>,
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
        for action in &input.actions {
            let InputActionKind::Message { message } = &action.action else {
                graph.push((action.sequence, action.after.clone(), true));
                continue;
            };
            if message.kind != MessageKind::Text {
                graph.push((action.sequence, action.after.clone(), true));
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
                    .or_insert(Some(action.sequence));
            }
        }
        Ok(Some(Self { requests, graph }))
    }

    fn independent(&self, keys: &[Key]) -> bool {
        let Some(sequences) = keys
            .iter()
            .map(|key| self.requests.get(key).copied().flatten())
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

    pub(super) fn alignment(&self, source: &[WireMessage], target: &[WireMessage]) -> Vec<usize> {
        let mut alignment = (0..target.len()).collect::<Vec<_>>();
        let mut start = 0;
        while start < source.len() {
            if key(&source[start]).is_none() {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < source.len() && key(&source[end]).is_some() {
                end += 1;
            }
            if end - start > 1 && end <= target.len() {
                self.align_run(source, target, start..end, &mut alignment);
            }
            start = end;
        }
        alignment
    }

    fn align_run(
        &self,
        source: &[WireMessage],
        target: &[WireMessage],
        run: std::ops::Range<usize>,
        alignment: &mut [usize],
    ) {
        let keys = source[run.clone()]
            .iter()
            .map(key)
            .collect::<Option<Vec<_>>>()
            .expect("ACK run");
        if !self.independent(&keys) {
            return;
        }
        let mut actual = BTreeMap::new();
        for index in run.clone() {
            let Some(key) = key(&target[index]) else {
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

fn key(message: &WireMessage) -> Option<Key> {
    if message.kind != MessageKind::Text {
        return None;
    }
    let EngineIoPacket::Message(packet) = decode_engine_io_text(&message.data, usize::MAX).ok()?
    else {
        return None;
    };
    if packet.kind != SocketIoKind::Ack || packet.attachments != 0 || !packet.binary.is_empty() {
        return None;
    }
    Some((packet.namespace, packet.id?))
}

#[cfg(test)]
mod tests;
