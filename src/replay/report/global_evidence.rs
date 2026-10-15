//! Exact Global counts and disk-backed, paginated unused-evidence details.
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::dependency_index::{PageManifest, PageWriter, Paged};
use crate::replay::ReplayState;

const PROTOCOLS: [&str; 6] = ["mysql", "redis", "memcached", "http", "kafka", "motan"];

pub(in crate::replay) struct GlobalDetails {
    pub(in crate::replay) manifests: Value,
    pages: Vec<Paged<Value>>,
}

impl GlobalDetails {
    pub(in crate::replay) fn commit(&self) {
        for pages in &self.pages {
            pages.persist();
        }
    }
}

pub(in crate::replay) async fn prepare(
    state: Arc<Mutex<ReplayState>>,
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
        for protocol in PROTOCOLS {
            let mut writer = PageWriter::<Value>::new_in(&root.join("global-dependencies"))?;
            let mut visit = |item| writer.push(item);
            match protocol {
                "mysql" => state.visit_global_mysql_unused(&mut visit)?,
                "redis" => state.redis.visit_global_unused(&mut visit)?,
                "memcached" => state.memcached.visit_global_unused(&mut visit)?,
                "http" => state.visit_global_http_unused(&mut visit)?,
                "kafka" => state.kafka.visit_global_unused(&mut visit)?,
                "motan" => state.motan.visit_global_unused(&mut visit)?,
                _ => unreachable!(),
            }
            let inventory = writer.finish()?;
            manifests.insert(
                protocol.into(),
                serde_json::to_value(inventory.manifest().relative_to(root)?)?,
            );
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

pub fn read_global_dependency_page(
    report: &Path,
    protocol: &str,
    offset: usize,
    limit: usize,
) -> Result<GlobalDependencyPage> {
    ensure!(
        PROTOCOLS.contains(&protocol),
        "unsupported Global dependency protocol {protocol:?}"
    );
    ensure!(
        (1..=1000).contains(&limit),
        "Global dependency page limit must be between 1 and 1000"
    );
    let root = report
        .parent()
        .context("Global report has no parent directory")?;
    let report: Value = serde_json::from_slice(&std::fs::read(report)?)?;
    ensure!(
        report["finalized"] == true,
        "Global dependency details require a finalized report"
    );
    let manifest: PageManifest =
        serde_json::from_value(report["global_evidence"][protocol].clone())
            .context("report lacks paginated Global evidence; use a fresh Replay on this engine")?;
    let inventory = Paged::<Value>::restore(manifest.resolve(root)?)?;
    // Reclassification is reversible and updates the report, while native pages
    // remain immutable. Project its Case witnesses after the native inventory.
    let events = match protocol {
        "mysql" => &report["unused_global_exchanges"],
        "http" => &report["unused_global_http_exchanges"],
        _ => &report[protocol]["unused_global"],
    };
    let overlay: Vec<_> = events
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| {
            event["background_original_case_id"].is_string() && event["background_rule"].is_string()
        })
        .collect();
    let total = inventory
        .count
        .checked_add(overlay.len())
        .context("Global detail count overflow")?;
    ensure!(offset <= total, "Global dependency offset exceeds count");
    let mut items = Vec::new();
    if offset < inventory.count {
        for page in inventory.page_for(offset)?..inventory.pages() {
            let start = inventory.page_start(page);
            for (index, item) in inventory.read_page(page)?.into_iter().enumerate() {
                if start + index < offset {
                    continue;
                }
                items.push(item);
                if items.len() == limit {
                    break;
                }
            }
            if items.len() == limit {
                break;
            }
        }
    }
    if items.len() < limit {
        items.extend(
            overlay
                .into_iter()
                .skip(offset.saturating_sub(inventory.count))
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

pub(crate) fn stage_global_evidence(source: &Path, destination: &Path) -> Result<()> {
    let report: Value = serde_json::from_slice(&std::fs::read(source)?)?;
    let Some(manifests) = report.get("global_evidence").and_then(Value::as_object) else {
        return Ok(());
    };
    let from = source
        .parent()
        .context("source Global report has no parent")?;
    let to = destination
        .parent()
        .context("staged Global report has no parent")?;
    if from == to {
        return Ok(());
    }
    for manifest in manifests.values() {
        serde_json::from_value::<PageManifest>(manifest.clone())?.stage_into(from, to)?;
    }
    Ok(())
}

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
