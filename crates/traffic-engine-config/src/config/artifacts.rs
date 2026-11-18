use std::path::PathBuf;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArtifactsConfig {
    pub root_dir: PathBuf,
}

impl ArtifactsConfig {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            !self.root_dir.as_os_str().is_empty(),
            "artifacts.root_dir must not be empty"
        );
        Ok(())
    }
}
