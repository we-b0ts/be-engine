//! Exact historical ownership repair after a sealed Socket.IO close.
use super::{
    model::{ClaimStatus, ProposedAttribution},
    rules,
    source::{self, SourceSnapshot},
};
use crate::{
    dependency::{attribution::DependencyOwner, observation::CapturePhase},
    interaction::model::{CLIENT_ABORT_LIMIT, EndObservation, EndReason, Protocol},
    rewrite::{model::RewriteState, verification_obligations::VerificationImpact},
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(super) const RULE_ID: &str = "engine.socketio_close_tail:v1";

pub(super) fn fingerprint() -> String {
    source::digest(RULE_ID.as_bytes())
}

fn request(source: &SourceSnapshot, case: Uuid) -> Result<Value> {
    let directory = source
        .inputs
        .get(&case)
        .context("Source Case input is absent")?;
    Ok(serde_json::from_slice(
        &source.read_input(&directory.join("request.json"))?,
    )?)
}

fn started(request: &Value) -> Result<DateTime<Utc>> {
    Ok(serde_json::from_value(request["timestamp"].clone())?)
}

fn closed_at(source: &SourceSnapshot, case: Uuid) -> Result<DateTime<Utc>> {
    let request = request(source, case)?;
    let response: Value = serde_json::from_slice(
        &source.read_input(&source.inputs[&case].join("expected-response.json"))?,
    )?;
    ensure!(
        request["interaction"]["protocol"] == "socket_io"
            && response["interaction"]["protocol"] == "socket_io",
        "close-tail ownership requires a recorded Socket.IO origin"
    );
    let end: EndObservation = serde_json::from_value(response["interaction"]["end"].clone())?;
    ensure!(
        end.observes_close_tail(Protocol::SocketIo)
            && matches!(end.reason, EndReason::ClientClose | EndReason::ServerEof)
            && end.partial_message.is_none(),
        "origin has no complete Socket.IO close with pending work"
    );
    let offset = i64::try_from(end.offset_ms)
        .ok()
        .and_then(TimeDelta::try_milliseconds)
        .context("invalid Source Socket.IO close offset")?;
    started(&request)?
        .checked_add_signed(offset)
        .context("invalid Source Socket.IO close clock")
}

pub(super) fn bind(
    state: &RewriteState,
    source: &SourceSnapshot,
    proposal: &mut ProposedAttribution,
    active_rules: &BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        proposal.rule_binding.rule_ids == BTreeSet::from([RULE_ID.into()]),
        "Socket.IO close-tail attribution must bind only the engine contract"
    );
    let DependencyOwner::Case { origin_case_id, .. } = proposal.owner else {
        anyhow::bail!("Socket.IO close-tail attribution requires a proven origin Case");
    };
    let closed = closed_at(source, origin_case_id)?;
    let limit = closed
        .checked_add_signed(TimeDelta::from_std(CLIENT_ABORT_LIMIT)?)
        .context("invalid Source Socket.IO observation limit")?;
    let epochs: BTreeSet<_> = source
        .exchanges
        .values()
        .filter(|event| event.complete && event.capture.phase == CapturePhase::Runtime)
        .filter_map(|event| {
            matches!(event.capture.attribution, DependencyOwner::Case { origin_case_id: origin, .. }
                if origin == origin_case_id)
            .then_some(event.capture.process_epoch)
        })
        .collect();
    ensure!(
        epochs.len() == 1 && !proposal.source_exchange_ids.is_empty(),
        "Socket.IO close-tail ownership requires exact occurrences in one proven Source epoch"
    );
    let claimed: BTreeSet<_> = proposal
        .claim_ids
        .iter()
        .filter_map(|id| state.dependency_review.claims.get(id))
        .filter(|claim| {
            claim.recording_run_id == state.recording_run_id
                && claim.source_inventory_id == source.identity
                && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Unresolved)
        })
        .flat_map(|claim| claim.source_exchange_ids.iter().copied())
        .collect();
    let mut victims = BTreeMap::new();
    for id in &proposal.source_exchange_ids {
        let event = source
            .exchanges
            .get(id)
            .context("Source occurrence is absent")?;
        let capture = &event.capture;
        ensure!(
            event.complete
                && capture.semantic_required
                && capture.phase == CapturePhase::Runtime
                && epochs.contains(&capture.process_epoch)
                && (closed..=limit).contains(&capture.started_at),
            "Source occurrence falls outside the proven Socket.IO close tail"
        );
        let owner = state
            .dependency_review
            .decisions
            .get(id)
            .filter(|decision| rules::current(*decision, active_rules))
            .map(|decision| &decision.owner)
            .or_else(|| source.case_defaults.get(id))
            .unwrap_or(&capture.attribution);
        match *owner {
            DependencyOwner::Unattributed { .. } => {}
            DependencyOwner::Case {
                origin_case_id: victim,
                ..
            } if victim != origin_case_id && claimed.contains(id) => {
                if let std::collections::btree_map::Entry::Vacant(entry) = victims.entry(victim) {
                    entry.insert(started(&request(source, victim)?)?);
                }
                ensure!(
                    (closed..=capture.started_at).contains(&victims[&victim]),
                    "claimed Source occurrence does not belong to a later Case"
                );
            }
            _ => anyhow::bail!(
                "Socket.IO close-tail proof requires an ownerless or explicitly claimed occurrence"
            ),
        }
    }
    if proposal.impact != VerificationImpact::MissingCapture {
        proposal.impact = VerificationImpact::Runtime;
    }
    Ok(())
}
