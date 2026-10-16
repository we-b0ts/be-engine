//! Local regression inputs, kept outside project and target fingerprints.
use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

pub(crate) const PATH: &str = ".traffic-e2e/regression.yaml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegressionScope {
    #[serde(default)]
    pub(crate) auto_next: bool,
    pub(crate) recording_run_id: Option<String>,
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
        let mut policy: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("invalid regression scope {}", path.display()))?;
        policy.recording_run_id = policy.recording_run_id.filter(|run_id| !run_id.is_empty());
        if let Some(run_id) = &policy.recording_run_id {
            ensure!(
                run_id.len() == 14 && run_id.bytes().all(|byte| byte.is_ascii_digit()),
                "{PATH}: recording_run_id must be a 14-digit existing recording run ID"
            );
        }
        for list in policy.only.iter().chain(policy.skip.iter()) {
            let mut seen = BTreeSet::new();
            for api in list {
                let parsed = api
                    .parse::<crate::recording_api::RecordingApiScope>()
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
        let api = crate::recording_api::identity(api);
        self.only
            .as_ref()
            .is_none_or(|apis| apis.is_empty() || apis.iter().any(|item| item == api))
            && self
                .skip
                .as_ref()
                .is_none_or(|apis| apis.iter().all(|item| item != api))
    }
}

pub(crate) const GITIGNORE_RULE: &str = "/.traffic-e2e/regression.yaml";
pub(crate) const GIT_PATHSPEC: &str = ":(exclude).traffic-e2e/regression.yaml";
pub(crate) const TEMPLATE: &str = "# Local regression settings; not committed or included in target fingerprints.\n# Set recording_run_id to reuse a completed standard recording; missing runs block progress.\n# Without a pin, rewrite selects an existing completed run and keeps it fixed.\n# recording_run_id: \"20260911093000\"\n# HTTP API routes must match backend-rewrite inventory exactly, without methods.\n# Each route includes all its recorded methods.\n# Exact paths preserve trailing/repeated slashes; wildcard patterns stay canonical.\n# Omitted or empty only selects all APIs; skip takes precedence.\n# only:\n#   - \"/api/users/*\"\n# Continue only successful Replay when the existing scheduler selects Replay again.\nauto_next: false\nonly: []\nskip: []\n";

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
    fn auto_next_defaults_to_false_and_requires_a_boolean() {
        let root = tempfile::tempdir().unwrap();
        initialize(root.path()).unwrap();
        assert!(!RegressionScope::load(root.path()).unwrap().auto_next);
        for (yaml, enabled) in [
            ("only: []\n", false),
            ("auto_next: false\n", false),
            ("auto_next: true\n", true),
        ] {
            std::fs::write(root.path().join(PATH), yaml).unwrap();
            assert_eq!(
                RegressionScope::load(root.path()).unwrap().auto_next,
                enabled
            );
        }
        std::fs::write(root.path().join(PATH), "auto_next: sometimes\n").unwrap();
        assert!(RegressionScope::load(root.path()).is_err());
    }

    #[test]
    fn initialization_is_idempotent_and_preserves_local_scope() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".gitignore"), "/target/").unwrap();
        initialize(root.path()).unwrap();
        assert!(
            RegressionScope::load(root.path())
                .unwrap()
                .includes("GET /a")
        );
        std::fs::write(root.path().join(PATH), "skip: [/a]\n").unwrap();
        initialize(root.path()).unwrap();
        assert!(
            !RegressionScope::load(root.path())
                .unwrap()
                .includes("GET /a")
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
                .includes("GET /a")
        );
    }
}

#[cfg(test)]
mod literal_path_tests {
    use super::*;
    #[test]
    fn skip_is_exact_for_raw_paths_and_never_aliases_the_plain_route() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".traffic-e2e")).unwrap();
        std::fs::write(
            root.path().join(PATH),
            "skip: [/api/v1/auth/tokens/, /api//other]\n",
        )
        .unwrap();
        let policy = RegressionScope::load(root.path()).unwrap();
        assert!(!policy.includes("POST /api/v1/auth/tokens/"));
        assert!(!policy.includes("GET /api/v1/auth/tokens/"));
        assert!(policy.includes("POST /api/v1/auth/tokens"));
        assert!(policy.includes("POST /api/other"));
        for invalid in [
            "/api/*/",
            "/api//*/x",
            "/api/a?x=1",
            "/api/a#fragment",
            "/api/a b",
        ] {
            std::fs::write(
                root.path().join(PATH),
                serde_yaml::to_string(&serde_json::json!({"skip":[invalid]})).unwrap(),
            )
            .unwrap();
            assert!(RegressionScope::load(root.path()).is_err(), "{invalid}");
        }
    }
}
