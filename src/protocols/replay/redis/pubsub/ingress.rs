//! Finite remote Socket.IO calls proven by original Redis and Case evidence.
use super::*;
use crate::dependency_index::RecordRef;
use crate::replay::ReplayCase;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};

mod causal;
mod driver;
mod preparation;
mod unanswered;
pub(crate) use driver::start;

type Wire = (Uuid, u64);
type Key = (TargetKey, Vec<u8>, rpc::Identity);

#[derive(Debug, Default)]
pub(super) struct Ingress {
    entries: Vec<Entry>,
    callbacks: HashMap<Wire, usize>,
    slots: HashSet<PushId>,
    observed: Option<causal::LiveEvents>,
}

#[derive(Debug, Clone)]
struct Frame {
    reference: Option<RecordRef>,
    inline: Vec<u8>,
}

impl Frame {
    fn bytes(&self) -> Result<Vec<u8>> {
        match &self.reference {
            Some(reference) => reference.load::<RecordedPush>()?.response.decode(),
            None => Ok(self.inline.clone()),
        }
    }
}

#[derive(Debug)]
struct Entry {
    case: String,
    source: rpc::Identity,
    reply: Option<Wire>,
    target_sid: Option<String>,
    endpoint: TargetKey,
    channel: Vec<u8>,
    slot: PushId,
    anchor: Wire,
    frame: Frame,
    offset: chrono::TimeDelta,
    ordinal: usize,
    reserved: bool,
    delivered_at: Option<tokio::time::Instant>,
    failed: bool,
    prerequisites: Vec<causal::Prerequisite>,
}

impl Ingress {
    pub(super) fn timing_evidence(
        &self,
        case: &str,
        start: DateTime<Utc>,
    ) -> Vec<crate::replay::control::input_timing::Evidence> {
        use crate::replay::control::input_timing::Evidence;
        self.entries
            .iter()
            .filter(|entry| entry.case == case)
            .filter_map(|entry| {
                let at = start.checked_add_signed(entry.offset)?;
                Some(Evidence {
                    reference: entry.slot.timing_reference(),
                    completed_at: at,
                    individual: true,
                })
            })
            .collect()
    }
    pub(super) fn owns_callback(&self, exchange: &ReplayExchange) -> bool {
        self.callbacks
            .get(&(
                exchange.record.native.connection_id,
                exchange.record.native.sequence,
            ))
            .is_some_and(|&index| exchange.case_id.as_deref() == Some(&self.entries[index].case))
    }

    pub(super) fn requires_subscription(&self, exchange: &ReplayExchange) -> bool {
        self.entries.iter().any(|entry| {
            entry.anchor
                == (
                    exchange.record.native.connection_id,
                    exchange.record.native.sequence,
                )
        })
    }

    pub(super) fn comparison(
        &self,
        exchange: &ReplayExchange,
        args: &[Vec<u8>],
    ) -> Option<RpcComparison> {
        let &index = self.callbacks.get(&(
            exchange.record.native.connection_id,
            exchange.record.native.sequence,
        ))?;
        let entry = &self.entries[index];
        if entry.delivered_at.is_none()
            || entry.failed
            || args.len() != 2
            || args[0] != entry.channel
        {
            return None;
        }
        let (actual, actual_value) = rpc::callback(&args[1]).ok().flatten()?;
        let (source, mut expected) = rpc::callback(&exchange.args[1]).ok().flatten()?;
        if source != entry.source
            || actual.host != source.host
            || actual.namespace != source.namespace
            || actual.id != source.id
            || entry.target_sid.as_deref() != Some(&actual.sid)
        {
            return None;
        }
        // Remote host and counter are inputs, not locally generated IDs. Only
        // the session already observed independently on Target is translated.
        expected["sid"] = actual.sid.into();
        Some(RpcComparison {
            source: vec![
                exchange.args[0].clone(),
                serde_json::to_vec(&expected).ok()?,
            ],
            actual: vec![args[0].clone(), serde_json::to_vec(&actual_value).ok()?],
        })
    }
}

impl PubSubState {
    pub(in crate::protocols::replay::redis) fn pending_ingress_reply(
        &self,
        case: Option<&str>,
        endpoint: &TargetKey,
        command: &str,
        args: &[Vec<u8>],
    ) -> bool {
        if command != "PUBLISH" || args.len() != 2 {
            return false;
        }
        let Some((actual, _)) = rpc::callback(&args[1]).ok().flatten() else {
            return false;
        };
        self.ingress.entries.iter().any(|entry| {
            entry.reply.is_some()
                && entry.reserved
                && entry.delivered_at.is_none()
                && !entry.failed
                && Some(entry.case.as_str()) == case
                && entry.endpoint == *endpoint
                && entry.channel == args[0]
                && actual.host == entry.source.host
                && actual.namespace == entry.source.namespace
                && actual.id == entry.source.id
                && entry.target_sid.as_deref() == Some(&actual.sid)
        })
    }

    pub(super) fn complete_ingress(&mut self, slot: PushId) {
        for entry in &mut self.ingress.entries {
            if entry.slot == slot {
                entry.delivered_at = Some(tokio::time::Instant::now());
            }
        }
    }

    pub(super) fn fail_ingress(&mut self, slot: PushId) {
        for entry in &mut self.ingress.entries {
            if entry.slot == slot {
                entry.failed = true;
            }
        }
    }

    pub(super) fn timer_is_correlated(
        &self,
        id: PushId,
        digest: Option<[u8; 32]>,
        namespace: Option<&str>,
    ) -> bool {
        self.ingress.slots.contains(&id)
            || self.timer_controls_echo(id, digest)
            || self.native_clock.guards(namespace)
    }

    pub(super) fn push_available(&self, id: PushId) -> bool {
        match id {
            PushId::Inline(index) => self.pushes[index].status.is_available(),
            PushId::Indexed { lane, index } => self.indexed.available(lane, index),
        }
    }

    pub(super) fn reserve_push(&mut self, id: PushId) {
        match id {
            PushId::Inline(index) => self.pushes[index].status = ReplayExchangeStatus::Responding,
            PushId::Indexed { lane, index } => self.indexed.responding(lane, index),
        }
    }
}
