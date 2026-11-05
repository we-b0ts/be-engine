//! Source-proven reassignment of later unused occurrences after client abort.
use super::{
    model::{ClaimStatus, ForeignUnusedClaim, ProposedAttribution},
    source::{self, SourceSnapshot},
};
use crate::dependency::attribution::DependencyOwner;
use crate::interaction::model::EndObservation;
use crate::rewrite::{model::RewriteState, verification_obligations::VerificationImpact};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(super) const RULE_ID: &str = "engine.client_abort_tail:v1";

pub(super) fn fingerprint() -> String {
    source::digest(RULE_ID.as_bytes())
}

fn request(source: &SourceSnapshot, case: &Uuid) -> Result<Value> {
    let directory = source
        .inputs
        .get(case)
        .context("Source Case input is absent")?;
    Ok(serde_json::from_slice(
        &source.read_input(&directory.join("request.json"))?,
    )?)
}

fn request_start(request: &Value) -> Result<DateTime<Utc>> {
    Ok(serde_json::from_value(request["timestamp"].clone())?)
}

fn aborted_at(
    source: &SourceSnapshot,
    case: &Uuid,
    request: &Value,
) -> Result<Option<DateTime<Utc>>> {
    let Some(last) = request["interaction"]["actions"]
        .as_array()
        .and_then(|items| items.last())
    else {
        return Ok(None);
    };
    if last["action"]["kind"] != "transport_end"
        || !matches!(last["action"]["end"].as_str(), Some("eof" | "reset"))
    {
        return Ok(None);
    }
    let directory = &source.inputs[case];
    let response: Value =
        serde_json::from_slice(&source.read_input(&directory.join("expected-response.json"))?)?;
    let protocol = request["interaction"]["protocol"].as_str();
    if !matches!(protocol, Some("socket_io" | "web_socket"))
        || response["interaction"]["protocol"].as_str() != protocol
    {
        return Ok(None);
    }
    let end: EndObservation = serde_json::from_value(response["interaction"]["end"].clone())?;
    if !end.interrupted_by_client() {
        return Ok(None);
    }
    let offset = last["offset_ms"]
        .as_i64()
        .filter(|offset| *offset >= 0)
        .and_then(TimeDelta::try_milliseconds)
        .context("invalid Source client-end offset")?;
    Ok(Some(
        request_start(request)?
            .checked_add_signed(offset)
            .context("invalid Source client-end clock")?,
    ))
}

pub(super) fn candidates(source: &SourceSnapshot, claims: &[ForeignUnusedClaim]) -> Vec<Value> {
    let mut victims = BTreeMap::new();
    for id in claims.iter().flat_map(|claim| &claim.source_exchange_ids) {
        let Some(event) = source.exchanges.get(id) else {
            continue;
        };
        if let DependencyOwner::Case {
            origin_case_id: victim,
            ..
        } = &event.capture.attribution
        {
            victims.entry(*victim).or_insert_with(|| {
                request(source, victim)
                    .and_then(|request| request_start(&request))
                    .ok()
            });
        }
    }
    let Some(latest_victim) = victims.values().flatten().max().copied() else {
        return vec![];
    };
    let mut origins = source
        .inputs
        .keys()
        .filter_map(|case| {
            let request = request(source, case).ok()?;
            if request_start(&request).ok()? >= latest_victim {
                return None;
            }
            let at = aborted_at(source, case, &request).ok()??;
            let later = victims
                .iter()
                .filter_map(|(victim, start)| start.filter(|start| *start > at).map(|_| victim))
                .collect::<Vec<_>>();
            (!later.is_empty()).then(|| {
                (
                    at,
                    json!({"origin_case_id":case,
            "method_api":source.apis.get(case),"source_client_aborted_at":at,
            "later_claimed_cases":later,"rule_id":RULE_ID,
            "association":"temporal candidate only; Source call-chain proof is required"}),
                )
            })
        })
        .collect::<Vec<_>>();
    origins.sort_unstable_by_key(|(at, _)| std::cmp::Reverse(*at));
    origins
        .into_iter()
        .take(16)
        .map(|(_, candidate)| candidate)
        .collect()
}

pub(super) fn bind(
    state: &RewriteState,
    source: &SourceSnapshot,
    proposal: &mut ProposedAttribution,
) -> Result<()> {
    ensure!(
        proposal.rule_binding.rule_ids == BTreeSet::from([RULE_ID.into()]),
        "client-abort attribution must bind only the engine's client-abort contract"
    );
    let DependencyOwner::Case {
        origin_case_id: origin,
        ..
    } = &proposal.owner
    else {
        anyhow::bail!("client-abort attribution requires a proven earlier origin Case");
    };
    let origin_request = request(source, origin)?;
    let abort = aborted_at(source, origin, &origin_request)?
        .context("origin has no sealed premature client transport end")?;
    let claimed = proposal
        .claim_ids
        .iter()
        .map(|id| {
            state
                .dependency_review
                .claims
                .get(id)
                .filter(|claim| {
                    claim.recording_run_id == state.recording_run_id
                        && claim.source_inventory_id == source.identity
                        && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Unresolved)
                })
                .context("client-abort attribution requires a current unused ownership claim")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flat_map(|claim| claim.source_exchange_ids.iter().copied())
        .collect::<BTreeSet<_>>();
    ensure!(
        !proposal.source_exchange_ids.is_empty()
            && proposal.source_exchange_ids.is_subset(&claimed),
        "client-abort attribution must select exact unused occurrences from the current claims"
    );
    let epochs = source
        .exchanges
        .values()
        .filter_map(|event| {
            matches!(&event.capture.attribution, DependencyOwner::Case { origin_case_id, .. }
            if origin_case_id == origin)
            .then_some(event.capture.process_epoch)
        })
        .collect::<BTreeSet<_>>();
    ensure!(
        epochs.len() == 1,
        "client-abort origin requires one proven Source process epoch"
    );
    let mut victim_starts = BTreeMap::new();
    for id in &proposal.source_exchange_ids {
        let event = source
            .exchanges
            .get(id)
            .context("unused Source occurrence is absent")?;
        let DependencyOwner::Case {
            origin_case_id: victim,
            ..
        } = &event.capture.attribution
        else {
            anyhow::bail!("client-abort claim must be captured in a later Case");
        };
        if let std::collections::btree_map::Entry::Vacant(entry) = victim_starts.entry(*victim) {
            entry.insert(request_start(&request(source, victim)?)?);
        }
        let victim_start = victim_starts[victim];
        ensure!(
            event.complete
                && event.capture.semantic_required
                && epochs.contains(&event.capture.process_epoch)
                && victim_start > abort
                && event.capture.started_at >= victim_start,
            "client-abort claim does not belong to a later Case in the origin process epoch"
        );
    }
    // The victim's scope loses only the proved occurrences. The effective
    // origin still needs an actual Replay against its new dependency inventory.
    proposal.impact = VerificationImpact::Runtime;
    Ok(())
}
