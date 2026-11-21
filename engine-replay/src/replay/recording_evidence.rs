//! Bounded recording traversal and original dependency envelope metadata.
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub fn files(source: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    crate::dependency_index::recording_files(source)
}

pub fn case_id(file: &Path) -> Result<String> {
    Ok(file
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .context("recorded case has no identity")?
        .to_string())
}

/// Read only the physical dependency clock; a primary API timestamp is never a substitute.
pub fn dependency_started_at(event: &serde_json::Value) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Some(started) = event["request_started_at"].as_str() {
        return started.parse().ok();
    }
    let completed: chrono::DateTime<chrono::Utc> = event["timestamp"].as_str()?.parse().ok()?;
    let millis = i64::try_from(event["duration_ms"].as_u64()?).ok()?;
    completed.checked_sub_signed(chrono::TimeDelta::try_milliseconds(millis)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dependency_start_uses_its_envelope_and_never_an_api_clock() {
        let completed = json!({"timestamp":"2026-01-01T00:00:03Z", "duration_ms":2500});
        assert_eq!(
            dependency_started_at(&completed).unwrap().to_rfc3339(),
            "2026-01-01T00:00:00.500+00:00"
        );
        let mut exact = completed.clone();
        exact["request_started_at"] = json!("2026-01-01T00:00:00.499999Z");
        assert_eq!(
            dependency_started_at(&exact).unwrap().timestamp_micros(),
            1_767_225_600_499_999
        );
        for event in [
            json!({"target_request_started_at":"2026-01-01T00:00:00Z"}),
            json!({"timestamp":"2026-01-01T00:00:03Z"}),
            json!({"timestamp":"2026-01-01T00:00:03Z", "duration_ms":u64::MAX}),
        ] {
            assert!(dependency_started_at(&event).is_none());
        }
    }
}
