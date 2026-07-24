use std::path::Path;

use anyhow::{Context, Result, ensure};

pub(crate) fn directory_name(target_root: &Path) -> Result<String> {
    let name = target_root
        .file_name()
        .and_then(|name| name.to_str())
        .context("target repository directory name must be valid UTF-8")?;
    ensure!(
        name.chars()
            .any(|character| character.is_ascii_alphanumeric()),
        "target repository directory name must contain a letter or digit"
    );
    Ok(name.to_string())
}
