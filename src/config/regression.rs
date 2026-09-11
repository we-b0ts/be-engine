//! Standalone coordinator selection policy; never changes recording or Replay inputs.
use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

pub(crate) const PATH: &str = ".traffic-e2e/regression.yaml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegressionScope {
    #[serde(default = "default_require_comparison")]
    pub(crate) require_comparison: bool,
    only: Option<Vec<String>>,
    skip: Option<Vec<String>>,
}

impl RegressionScope {
    pub(crate) fn load(target_root: &Path) -> Result<Self> {
        let path = target_root.join(PATH);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let policy: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("invalid regression scope {}", path.display()))?;
        ensure!(
            policy.only.as_ref().is_none_or(|apis| !apis.is_empty()),
            "{PATH}: only must contain at least one API"
        );
        for list in policy.only.iter().chain(policy.skip.iter()) {
            let mut seen = BTreeSet::new();
            for api in list {
                let parsed = api
                    .parse::<crate::RecordingApi>()
                    .with_context(|| format!("{PATH}: invalid API {api:?}"))?;
                ensure!(
                    parsed.to_string() == *api,
                    "{PATH}: use canonical inventory API {:?}",
                    parsed.to_string()
                );
                ensure!(seen.insert(api), "{PATH}: duplicate API {api:?}");
            }
        }
        Ok(policy)
    }

    pub(crate) fn selectors(&self) -> impl Iterator<Item = &String> {
        self.only.iter().chain(self.skip.iter()).flatten()
    }

    pub(crate) fn includes(&self, api: &str) -> bool {
        self.only
            .as_ref()
            .is_none_or(|apis| apis.iter().any(|item| item == api))
            && self
                .skip
                .as_ref()
                .is_none_or(|apis| apis.iter().all(|item| item != api))
    }
}

pub(crate) const GITIGNORE_RULE: &str = "/.traffic-e2e/regression.yaml";
pub(crate) const GIT_PATHSPEC: &str = ":(exclude).traffic-e2e/regression.yaml";
pub(crate) const TEMPLATE: &str = "# Local regression settings; not committed or included in target fingerprints.\n# API names must match backend-rewrite inventory exactly.\n# Omit only to select all APIs; skip takes precedence.\n# only:\n#   - \"GET /api/users/*\"\nskip: []\nrequire_comparison: true\n";

pub(crate) fn default_require_comparison() -> bool {
    true
}

impl Default for RegressionScope {
    fn default() -> Self {
        Self {
            only: None,
            skip: None,
            require_comparison: true,
        }
    }
}

/// Low-level project initialization also installs the local policy without
/// replacing user choices. Full repository initialization creates it atomically
/// alongside its other generated files.
pub(crate) fn initialize(target_root: &Path) -> Result<()> {
    for name in [".gitignore", ".dockerignore"] {
        let path = target_root.join(name);
        let mut contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        if !contents.lines().any(|line| line.trim() == GITIGNORE_RULE) {
            if !contents.is_empty() && !contents.ends_with('\n') {
                contents.push('\n');
            }
            contents.push_str(GITIGNORE_RULE);
            contents.push('\n');
            if path.exists() {
                super::edit::write_atomic(&path, contents.as_bytes())?;
            } else {
                super::edit::create_atomic(&path, contents.as_bytes())?;
            }
        }
    }
    let path = target_root.join(PATH);
    if !path.exists() {
        super::edit::create_many_atomic(&[(path, TEMPLATE.as_bytes().to_vec())])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_is_idempotent_preserves_local_choices_and_defaults_true() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".gitignore"), "/target/").unwrap();
        initialize(root.path()).unwrap();
        assert!(
            RegressionScope::load(root.path())
                .unwrap()
                .require_comparison
        );
        std::fs::write(
            root.path().join(PATH),
            "require_comparison: false\nskip: [GET /a]\n",
        )
        .unwrap();
        initialize(root.path()).unwrap();
        assert!(
            !RegressionScope::load(root.path())
                .unwrap()
                .require_comparison
        );
        for name in [".gitignore", ".dockerignore"] {
            let contents = std::fs::read_to_string(root.path().join(name)).unwrap();
            assert_eq!(
                contents
                    .lines()
                    .filter(|line| *line == GITIGNORE_RULE)
                    .count(),
                1
            );
        }
        std::fs::remove_file(root.path().join(PATH)).unwrap();
        assert!(
            RegressionScope::load(root.path())
                .unwrap()
                .require_comparison
        );
    }
}
