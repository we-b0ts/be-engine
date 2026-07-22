use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Deserialize)]
struct CaseKind {
    kind: String,
}

pub(crate) fn reject_online_compare(path: &Path) -> Result<()> {
    let marker = path.join("case-kind.json");
    if !marker.is_file() {
        return Ok(());
    }
    let kind: CaseKind = serde_json::from_slice(
        &std::fs::read(&marker)
            .with_context(|| format!("failed to read case kind {}", marker.display()))?,
    )
    .with_context(|| format!("invalid case kind {}", marker.display()))?;
    if kind.kind == "online_compare" {
        bail!(
            "online compare artifacts are not replay cases and cannot be used by prepare, case-group, or replay: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_online_compare_marker() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("case-kind.json"),
            r#"{"version":1,"kind":"online_compare"}"#,
        )
        .unwrap();
        let error = reject_online_compare(directory.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("online compare artifacts are not replay cases"));
    }
}
