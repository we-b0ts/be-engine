//! Exact Global counts, immutable inventories and lazy unused-evidence details.
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::dependency_index::{PageWriter, Paged};
use crate::replay::{ReplayProtocolSet, RuntimeState};
use traffic_replay::report::GlobalReportProjection;

pub(crate) mod artifact;
#[cfg(test)]
mod compact_tests;
pub(crate) mod preparation;
mod projection;
mod protocol;
pub(crate) mod regular;
mod regular_store;
pub(crate) mod regular_usage;
use protocol::{NativeInventory, ProtocolEvidence};

#[cfg(test)]
use crate::protocols::replay::report::{
    PROTOCOLS,
    artifacts::{read_global_dependency_page, stage_global_evidence},
};

pub(crate) struct GlobalDetails {
    pub(crate) manifests: Value,
    pages: Vec<Paged<Value>>,
}

impl GlobalDetails {
    pub(crate) fn commit(&self) {
        for pages in &self.pages {
            pages.persist();
        }
    }
}

pub(crate) async fn prepare<P: ReplayProtocolSet>(
    state: Arc<Mutex<RuntimeState<P>>>,
    report_path: &Path,
) -> Result<GlobalDetails> {
    let report_path = report_path.to_owned();
    tokio::task::spawn_blocking(move || {
        let state = state.blocking_lock();
        ensure!(
            state.finalized_at.is_some(),
            "Global detail publication requires finalized Replay state"
        );
        let mut manifests = serde_json::Map::new();
        let root = report_path
            .parent()
            .context("Global report has no parent directory")?;
        let mut pages = Vec::new();
        for protocol in state.global_report_protocols() {
            let protocol = protocol.as_str();
            state.global_report_layout(protocol)?;
            if let Some(regular) =
                regular::RegularEvidence::prepare(&report_path, &state, protocol)?
            {
                let extensions = state
                    .protocols
                    .global_report_extensions(protocol, &report_path)?;
                manifests.insert(
                    protocol.into(),
                    serde_json::to_value(ProtocolEvidence::new(protocol, regular, extensions))?,
                );
                continue;
            }
            let mut writer = PageWriter::<Value>::new_in(&root.join("global-dependencies"))?;
            let mut visit = |item| writer.push(item);
            if state.native.owns_global_report(protocol) {
                state.native.visit_global_unused(protocol, &mut visit)?;
            } else {
                P::visit_global_unused(&state, protocol, &mut visit)?;
            }
            let inventory = writer.finish()?;
            let manifest = inventory.manifest().relative_to(root)?;
            let value = state
                .protocols
                .global_report_fallback(protocol, &report_path, manifest)?;
            manifests.insert(protocol.into(), value);
            pages.push(inventory);
        }
        Ok(GlobalDetails {
            manifests: Value::Object(manifests),
            pages,
        })
    })
    .await
    .context("Global dependency detail publication failed")?
}

#[derive(Debug, Serialize)]
pub struct GlobalDependencyPage {
    pub protocol: String,
    pub total: usize,
    pub offset: usize,
    pub returned: usize,
    pub items: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

pub(crate) fn read_page(
    report: &Path,
    protocol: &str,
    offset: usize,
    limit: usize,
    codecs: &traffic_protocol::report::CodecRegistry,
) -> Result<GlobalDependencyPage> {
    ensure!(
        (1..=1000).contains(&limit),
        "Global dependency page limit must be between 1 and 1000"
    );
    let report_path = report;
    let report: Value = serde_json::from_slice(&std::fs::read(report_path)?)?;
    ensure!(
        report["finalized"] == true,
        "Global dependency details require a finalized report"
    );
    ensure!(
        report["global_evidence"]
            .as_object()
            .is_some_and(|sections| sections.contains_key(protocol)),
        "unsupported Global dependency protocol {protocol:?}"
    );
    let codec = codecs.codec(protocol);
    let inventory = NativeInventory::open(
        report_path,
        protocol,
        &report["global_evidence"][protocol],
        codec.as_deref(),
    )?;
    let native_count = inventory.count()?;
    // Reclassification is reversible and updates the report, while native pages
    // remain immutable. Project its Case witnesses after the native inventory.
    let events = codec.as_ref().map_or(
        &report["dependency_protocols"][protocol]["unused_global"],
        |codec| codec.reclassified_rows(&report, protocol),
    );
    let overlay: Vec<_> = events
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| {
            event["background_original_case_id"].is_string() && event["background_rule"].is_string()
        })
        .collect();
    let total = native_count
        .checked_add(overlay.len())
        .context("Global detail count overflow")?;
    ensure!(offset <= total, "Global dependency offset exceeds count");
    let mut items = Vec::new();
    inventory.read(report_path, offset, limit, &mut items)?;
    if items.len() < limit {
        items.extend(
            overlay
                .into_iter()
                .skip(offset.saturating_sub(native_count))
                .take(limit - items.len())
                .cloned(),
        );
    }
    let next = offset + items.len();
    Ok(GlobalDependencyPage {
        protocol: protocol.into(),
        total,
        offset,
        returned: items.len(),
        items,
        next_offset: (next < total).then_some(next),
    })
}

pub(crate) fn stage(
    source: &Path,
    destination: &Path,
    codecs: &traffic_protocol::report::CodecRegistry,
) -> Result<Option<Value>> {
    let mut report: Value = serde_json::from_slice(&std::fs::read(source)?)?;
    let Some(manifests) = report
        .get_mut("global_evidence")
        .and_then(Value::as_object_mut)
    else {
        return Ok(None);
    };
    let from = source
        .parent()
        .context("source Global report has no parent")?;
    let to = destination
        .parent()
        .context("staged Global report has no parent")?;
    if from == to {
        return Ok(None);
    }
    let mut rebound = false;
    for (protocol, value) in manifests.iter_mut() {
        let original = value.clone();
        protocol::stage(
            value,
            protocol,
            source,
            destination,
            codecs.codec(protocol).as_deref(),
        )?;
        rebound |= *value != original;
    }
    Ok(rebound.then_some(report))
}

#[cfg(test)]
use crate::protocols::replay::report::redis::{notifications, shared};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pages_keep_exact_counts_across_boundaries_overlays_and_publication() {
        let source = tempfile::tempdir().unwrap();
        let published = tempfile::tempdir().unwrap();
        let mut writer = PageWriter::new_in(&source.path().join("global-dependencies")).unwrap();
        for index in 0..600 {
            writer.push(json!({"index":index})).unwrap();
        }
        let pages = writer.finish().unwrap();
        let manifest = pages.persist().relative_to(source.path()).unwrap();
        let report = source.path().join("report.json");
        std::fs::write(
            &report,
            json!({"finalized":true,"global_evidence":{"redis":manifest},"redis":{
                "unused_global_count":602,"unused_global":[{"index":0},
                    {"index":600,"background_original_case_id":"case-a","background_rule":"worker"},
                    {"index":601,"background_original_case_id":"case-b","background_rule":"worker"}]
            }})
            .to_string(),
        )
        .unwrap();
        let page = read_global_dependency_page(&report, "redis", 255, 3).unwrap();
        assert_eq!(page.total, 602);
        assert_eq!(
            page.items,
            vec![
                json!({"index":255}),
                json!({"index":256}),
                json!({"index":257})
            ]
        );
        assert_eq!(page.next_offset, Some(258));
        let destination = published.path().join("replay-report.json");
        stage_global_evidence(&report, &destination).unwrap();
        std::fs::copy(&report, &destination).unwrap();
        source.close().unwrap();
        let page = read_global_dependency_page(&destination, "redis", 599, 3).unwrap();
        assert_eq!(page.items.len(), 3);
        assert_eq!(page.items[0]["index"], 599);
        assert_eq!(page.items[2]["index"], 601);
        assert_eq!(page.next_offset, None);
        assert!(
            read_global_dependency_page(&destination, "redis", 602, 100)
                .unwrap()
                .items
                .is_empty()
        );
        assert!(read_global_dependency_page(&destination, "redis", 603, 1).is_err());
        assert!(read_global_dependency_page(&destination, "redis", 0, 0).is_err());
    }
}
