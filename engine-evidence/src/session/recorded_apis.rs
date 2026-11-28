//! Recorded HTTP API inventory without walking the Source event stream.

use std::{collections::BTreeMap, path::Path};

use anyhow::Result;
use serde::Serialize;
use traffic_engine_config::config::api_catalog::{self, ApiCatalog};
use traffic_recording_store::session_summary;

#[derive(Debug, Serialize)]
pub struct RecordedApi {
    pub api: String,
    pub method: String,
    pub paths: Vec<String>,
    pub requests: u64,
    pub first_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

pub fn recorded_apis(target_root: &Path, recording_root: &Path) -> Result<Vec<RecordedApi>> {
    let catalog = ApiCatalog::load(&target_root.join(api_catalog::PATH))?.unwrap_or_default();
    let patterns = catalog.case_paths();
    let mut apis = BTreeMap::new();
    for route in session_summary::read(recording_root)?.routes {
        let pattern = api_catalog::matching_case_pattern(&patterns, &route.path);
        let label = format!("{} {}", route.method, pattern.unwrap_or(&route.path));
        let api = apis.entry(label.clone()).or_insert_with(|| RecordedApi {
            api: label,
            method: route.method,
            paths: Vec::new(),
            requests: 0,
            first_seq: route.first_seq,
            case_pattern: pattern.map(str::to_owned),
            group: pattern.and_then(|pattern| catalog.routes().get(pattern).cloned()),
        });
        api.paths.push(route.path);
        api.requests += route.requests;
        api.first_seq = api.first_seq.min(route.first_seq);
    }
    Ok(apis.into_values().collect())
}
