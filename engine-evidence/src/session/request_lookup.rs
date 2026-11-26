//! Select the first recorded request for one catalog case pattern.

use std::path::Path;

use anyhow::{Result, ensure};
use serde::Serialize;
use traffic_engine_config::config::api_catalog::{self, ApiCatalog};
use traffic_recording_store::session;

#[derive(Debug, Serialize)]
pub struct ApiRequest {
    pub request_seq: u64,
    pub method: String,
    pub path: String,
    pub offset_micros: u64,
    pub exchange: uuid::Uuid,
}

/// Apply the same route precedence as the recorded API inventory. The method
/// is part of each evidence row, while the catalog identity is path-only.
pub fn first_api_request(
    target_root: &Path,
    recording_root: &Path,
    case_pattern: &str,
    from_sequence: u64,
    after_sequence: u64,
    through_sequence: Option<u64>,
) -> Result<Option<ApiRequest>> {
    let catalog = ApiCatalog::load(&target_root.join(api_catalog::PATH))?.unwrap_or_default();
    ensure!(
        case_pattern.starts_with('/') && catalog.routes().contains_key(case_pattern),
        "case pattern {case_pattern:?} is not in the API catalog"
    );
    let Some(first_sequence) = after_sequence.checked_add(1) else {
        return Ok(None);
    };
    let sequences = from_sequence.max(first_sequence)..=through_sequence.unwrap_or(u64::MAX);
    if sequences.is_empty() {
        return Ok(None);
    }
    let patterns = catalog.case_paths();
    let request = session::first_primary_request(recording_root, sequences, |route| {
        api_catalog::matching_case_pattern(&patterns, &route.path) == Some(case_pattern)
    })?;
    Ok(request.map(|request| ApiRequest {
        request_seq: request.sequence,
        method: request.route.method,
        path: request.route.path,
        offset_micros: request.offset_micros,
        exchange: request.exchange,
    }))
}
