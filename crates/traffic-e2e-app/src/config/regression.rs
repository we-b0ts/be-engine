//! Local regression inputs, kept outside project and target fingerprints.
use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

pub(crate) const PATH: &str = ".traffic-e2e/regression.yaml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegressionScope {
    #[serde(default = "default_max_implementers")]
    pub(crate) max_implementers: usize,
    #[serde(default)]
    pub(crate) auto_next: bool,
    #[serde(default)]
    pub(crate) retry_failed_only: bool,
    #[serde(default)]
    pub(crate) replay_timing: Option<crate::replay::ReplayStreamTiming>,
    #[serde(default = "default_replay_interval_cap_ms")]
    pub(crate) replay_interval_cap_ms: u64,
    pub(crate) recording_run_id: Option<String>,
    only: Option<Vec<String>>,
    skip: Option<Vec<String>>,
}

const fn default_max_implementers() -> usize {
    16
}

const fn default_replay_interval_cap_ms() -> u64 {
    crate::replay::DEFAULT_REPLAY_STREAM_INTERVAL_CAP_MS
}

impl Default for RegressionScope {
    fn default() -> Self {
        Self {
            max_implementers: default_max_implementers(),
            auto_next: false,
            retry_failed_only: false,
            replay_timing: None,
            replay_interval_cap_ms: default_replay_interval_cap_ms(),
            recording_run_id: None,
            only: None,
            skip: None,
        }
    }
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
        ensure!(
            policy.max_implementers > 0,
            "{PATH}: max_implementers must be a positive integer"
        );
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

    pub(crate) fn only_apis(&self) -> &[String] {
        self.only.as_deref().unwrap_or_default()
    }

    pub(crate) fn skipped_apis(&self) -> &[String] {
        self.skip.as_deref().unwrap_or_default()
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
pub(crate) const TEMPLATE: &str = "# Local regression settings; not committed or included in target fingerprints.\n# Set recording_run_id to reuse a completed standard recording; missing runs block progress.\n# Without a pin, rewrite selects an existing completed run and keeps it fixed.\n# recording_run_id: \"20260911093000\"\n# HTTP API routes must match backend-rewrite inventory exactly, without methods.\n# Each route includes all its recorded methods.\n# Exact paths preserve trailing/repeated slashes; wildcard patterns stay canonical.\n# Omitted or empty only selects all APIs; skip takes precedence.\n# only:\n#   - \"/api/users/*\"\n# Continue only successful Replay when the existing scheduler selects Replay again.\nauto_next: false\n# Skip previously passed cases during repair Replay; final revalidation always runs all cases.\nretry_failed_only: false\n# Optional stream timing override: fast caps each ordinary Case Pub/Sub and successful HTTP stream gap.\n# Omitting replay_timing preserves Source timing; recorded preserves Source stream intervals.\n# replay_timing: fast\n# Fast-mode interval cap in milliseconds, including the first push/header; 0 removes artificial waits.\nreplay_interval_cap_ms: 5\n# Fixed implementation slots; a running workflow retains its original capacity.\nmax_implementers: 16\nonly: []\nskip: []\n";

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
    fn replay_timing_is_optional_and_accepts_only_supported_modes() {
        use crate::replay::ReplayStreamTiming::{Fast, Recorded};
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            RegressionScope::load(root.path()).unwrap().replay_timing,
            None
        );
        initialize(root.path()).unwrap();
        for (yaml, timing) in [
            ("only: []\n", None),
            ("replay_timing: fast\n", Some(Fast)),
            ("replay_timing: recorded\n", Some(Recorded)),
        ] {
            std::fs::write(root.path().join(PATH), yaml).unwrap();
            assert_eq!(
                RegressionScope::load(root.path()).unwrap().replay_timing,
                timing
            );
        }
        std::fs::write(root.path().join(PATH), "replay_timing: immediate\n").unwrap();
        assert!(RegressionScope::load(root.path()).is_err());
    }

    #[test]
    fn replay_interval_cap_defaults_to_five_and_accepts_zero() {
        let root = tempfile::tempdir().unwrap();
        initialize(root.path()).unwrap();
        assert_eq!(
            RegressionScope::load(root.path())
                .unwrap()
                .replay_interval_cap_ms,
            5
        );
        for cap in [0, 1, 50, u64::MAX] {
            std::fs::write(
                root.path().join(PATH),
                format!("replay_interval_cap_ms: {cap}\n"),
            )
            .unwrap();
            assert_eq!(
                RegressionScope::load(root.path())
                    .unwrap()
                    .replay_interval_cap_ms,
                cap
            );
        }
        for value in ["-1", "1.5", "null", "true", "fast"] {
            std::fs::write(
                root.path().join(PATH),
                format!("replay_interval_cap_ms: {value}\n"),
            )
            .unwrap();
            assert!(
                RegressionScope::load(root.path()).is_err(),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn failed_case_retry_is_opt_in_and_requires_a_boolean() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            !RegressionScope::load(root.path())
                .unwrap()
                .retry_failed_only
        );
        initialize(root.path()).unwrap();
        assert!(
            !RegressionScope::load(root.path())
                .unwrap()
                .retry_failed_only
        );
        for (document, expected) in [
            ("only: []\n", false),
            ("retry_failed_only: true\n", true),
            ("retry_failed_only: false\n", false),
        ] {
            std::fs::write(root.path().join(PATH), document).unwrap();
            assert_eq!(
                RegressionScope::load(root.path())
                    .unwrap()
                    .retry_failed_only,
                expected
            );
        }
        for value in ["null", "1", "sometimes", "[]"] {
            std::fs::write(
                root.path().join(PATH),
                format!("retry_failed_only: {value}\n"),
            )
            .unwrap();
            assert!(RegressionScope::load(root.path()).is_err());
        }
    }

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
    fn implementer_capacity_defaults_and_rejects_invalid_values() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            RegressionScope::load(root.path()).unwrap().max_implementers,
            16
        );
        initialize(root.path()).unwrap();
        for (document, expected) in [("only: []\n", 16), ("max_implementers: 4\n", 4)] {
            std::fs::write(root.path().join(PATH), document).unwrap();
            assert_eq!(
                RegressionScope::load(root.path()).unwrap().max_implementers,
                expected
            );
        }
        for value in ["0", "-1", "1.5", "null", "true", "many"] {
            std::fs::write(
                root.path().join(PATH),
                format!("max_implementers: {value}\n"),
            )
            .unwrap();
            assert!(
                RegressionScope::load(root.path()).is_err(),
                "accepted {value}"
            );
        }
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
