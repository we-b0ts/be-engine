use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Deserialize)]
struct CaseKind {
    kind: String,
}

pub(crate) fn reject_comparison_recording(path: &Path) -> Result<()> {
    let marker = path.join("case-kind.json");
    if !marker.is_file() {
        return Ok(());
    }
    let kind: CaseKind = serde_json::from_slice(
        &std::fs::read(&marker)
            .with_context(|| format!("failed to read case kind {}", marker.display()))?,
    )
    .with_context(|| format!("invalid case kind {}", marker.display()))?;
    if kind.kind == "comparison_recording" {
        bail!(
            "comparison recording artifacts are not replay cases and cannot be used by prepare, case-group, or replay: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_comparison_recording_marker() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("case-kind.json"),
            r#"{"version":1,"kind":"comparison_recording"}"#,
        )
        .unwrap();
        let error = reject_comparison_recording(directory.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("comparison recording artifacts are not replay cases"));
    }
}
