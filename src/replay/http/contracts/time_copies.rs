//! Keep the dependency's already checked timestamp pairs until successful delivery.
use super::*;
use crate::value_contract::time_copies::{TimeCopyPosition, TimeCopyRecord, global_leaves};

#[derive(Debug, Clone)]
pub(in crate::replay::http) struct PreparedRead {
    records: Vec<TimeCopyRecord>,
    completed: Option<chrono::DateTime<Utc>>,
}

pub(super) fn prepare(
    exchange: &ReplayHttpExchange,
    source: &[u8],
    target: &[u8],
    plan: &crate::policy::CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Result<PreparedRead> {
    let mut records = Vec::new();
    let Some(identity) = exchange.record.native.id.as_deref() else {
        return Ok(PreparedRead {
            records,
            completed: exchange.record.native.timestamp,
        });
    };
    let position = TimeCopyPosition::Http {
        host: &exchange.identity.target.host,
        port: exchange.identity.target.port,
        exchange: identity,
    };
    let mut observe =
        |source: &serde_json::Value, target: &serde_json::Value, prefix: &str| -> Result<()> {
            for leaf in global_leaves(source, plan, clocks)? {
                let target = target
                    .pointer(&leaf.pointer)
                    .context("delivered HTTP time field is absent")?;
                let pointer = format!("{prefix}{}", leaf.pointer);
                records.push(TimeCopyRecord::new_time(
                    &leaf.time,
                    position,
                    position,
                    &pointer,
                    &pointer,
                    &leaf.value,
                    target,
                )?);
                anyhow::ensure!(
                    records.len() <= 4096,
                    "HTTP time provenance exceeds its bound"
                );
            }
            Ok(())
        };
    if let Some(logical) = crate::json_value::parse(source) {
        let delivered = if source == target {
            None
        } else {
            Some(crate::json_value::parse(target).context("delivered HTTP JSON changed encoding")?)
        };
        observe(&logical, delivered.as_ref().unwrap_or(&logical), "")?;
    } else if let Ok(document) = crate::value_codec::sse::Document::decode(source) {
        let delivered = if source == target {
            None
        } else {
            Some(crate::value_codec::sse::Document::decode(target)?)
        };
        let delivered = delivered.as_ref().unwrap_or(&document);
        anyhow::ensure!(
            document.events.len() == delivered.events.len(),
            "HTTP stream time inventory changed"
        );
        for (index, (source, target)) in document.events.iter().zip(&delivered.events).enumerate() {
            if let Some(source) = crate::json_value::parse(source.data.as_bytes()) {
                let target = crate::json_value::parse(target.data.as_bytes())
                    .context("delivered SSE JSON changed encoding")?;
                observe(&source, &target, &format!("/events/{index}"))?;
            }
        }
    }
    Ok(PreparedRead {
        records,
        completed: exchange.record.native.timestamp,
    })
}

pub(in crate::replay::http) fn commit(
    policy: Option<&ReplayPolicyRuntime>,
    exchange: &mut ReplayHttpExchange,
) -> Result<()> {
    let Some(read) = exchange.time_copy_delivery.take() else {
        return Ok(());
    };
    if read.records.is_empty() {
        return Ok(());
    }
    let owner = &policy
        .context("HTTP time provenance requires its policy")?
        .request_contracts;
    let case = exchange
        .case_id
        .as_deref()
        .context("HTTP time provenance requires its case")?;
    owner.record_time_copies(
        case,
        read.records,
        crate::value_contract::time::ClockPair {
            source: read.completed,
            target: Some(Utc::now()),
        },
    )
}

#[cfg(test)]
mod tests;
