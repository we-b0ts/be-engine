use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use uuid::Uuid;

/// Writes a replaceable active-run artifact atomically without durable sync.
/// Terminal publication makes the completed snapshot durable as a whole.
pub(super) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>> {
    let mut payload = serde_json::to_vec_pretty(value)?;
    payload.push(b'\n');
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("active artifact path has no UTF-8 file name")?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4()));
    fs::write(&temporary, &payload)
        .with_context(|| format!("failed to write active artifact {}", temporary.display()))?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("failed to publish active artifact {}", path.display()));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_exact_published_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("detail.json");

        let bytes = write_json(&path, &serde_json::json!({"passed": true})).unwrap();

        assert_eq!(fs::read(path).unwrap(), bytes);
        assert!(bytes.ends_with(b"\n"));
    }
}
