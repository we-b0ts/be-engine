//! The HTTP primary adapter projects an independent client-close input clock.
use crate::interaction::model::{InputActionKind, InputTranscript, Protocol};
use crate::replay::protocol_runtime::primary_close::SourceInput;
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Deserialize)]
struct Request {
    timestamp: DateTime<Utc>,
    interaction: InputTranscript,
}

#[derive(Deserialize)]
struct Admission {
    case_id: String,
    timestamp: DateTime<Utc>,
}

pub fn project(directory: &std::path::Path, case_id: &str) -> Result<Option<SourceInput>> {
    let raw = crate::request_headers::load_request_file(&directory.join("request.json"))?;
    let request: Request = serde_json::from_slice(&raw)?;
    request.interaction.validate()?;
    if !matches!(
        request.interaction.protocol,
        Protocol::Sse | Protocol::Ndjson
    ) {
        return Ok(None);
    }
    let [action] = request.interaction.actions.as_slice() else {
        return Ok(None);
    };
    if action.sequence != 1
        || !action.after.is_empty()
        || action.gap_start_ms.is_some()
        || action.ack_ref.is_some()
        || action.compressible_gap
        || !matches!(&action.action, InputActionKind::Close {code:None,reason} if reason.is_empty())
    {
        return Ok(None);
    }
    // Older response-adopted HTTP captures wrote request.timestamp at headers.
    // Admission is the independently recorded origin of their input offsets.
    let admission = directory.join("admission.json");
    let epoch = if admission.is_file() {
        let admission: Admission = serde_json::from_slice(&std::fs::read(admission)?)?;
        let scope = crate::dependency_index::scoped::case_path(directory);
        let matches_local_case = admission.case_id.starts_with("case-")
            && directory
                .file_name()
                .is_some_and(|name| name == admission.case_id.as_str())
            && matches!(
                crate::dependency_index::scoped::read_index(&scope)?.scope,
                traffic_model::recording::ScopeKind::Case { case_id: id }
                    if id.to_string() == case_id
            );
        ensure!(
            admission.case_id == case_id || matches_local_case,
            "HTTP timing admission belongs to another Case"
        );
        admission.timestamp.min(request.timestamp)
    } else {
        request.timestamp
    };
    Ok(Some(SourceInput {
        epoch,
        close_ms: action.offset_ms,
    }))
}

#[cfg(test)]
mod tests;
