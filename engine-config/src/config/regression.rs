//! Local regression inputs, kept outside project and target fingerprints.
use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, de::DeserializeOwned};

pub const PATH: &str = ".traffic-e2e/regression.yaml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRegression {
    pub recording_run_id: Option<String>,
    #[serde(default = "default_max_implementers")]
    pub max_implementers: usize,
}

impl Default for SessionRegression {
    fn default() -> Self {
        Self {
            recording_run_id: None,
            max_implementers: default_max_implementers(),
        }
    }
}

impl SessionRegression {
    pub fn load(target_root: &Path) -> Result<Self> {
        let mut policy: Self = load(target_root)?;
        ensure!(
            (1..=16).contains(&policy.max_implementers),
            "{PATH}: Session max_implementers must be between 1 and 16"
        );
        policy.recording_run_id = normalize_recording_run_id(policy.recording_run_id)?;
        Ok(policy)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionScope {
    #[serde(default = "default_max_implementers")]
    pub max_implementers: usize,
    #[serde(default)]
    pub auto_next: bool,
    #[serde(default)]
    pub retry_failed_only: bool,
    #[serde(default)]
    pub replay_timing: Option<crate::replay::ReplayStreamTiming>,
    #[serde(default = "default_replay_interval_cap_ms")]
    pub replay_interval_cap_ms: u64,
    pub recording_run_id: Option<String>,
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
    pub fn load(target_root: &Path) -> Result<Self> {
        let mut policy: Self = load(target_root)?;
        ensure!(
            policy.max_implementers > 0,
            "{PATH}: max_implementers must be a positive integer"
        );
        policy.recording_run_id = normalize_recording_run_id(policy.recording_run_id)?;
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

    pub fn selectors(&self) -> impl Iterator<Item = &String> {
        self.only.iter().chain(self.skip.iter()).flatten()
    }

    pub fn only_apis(&self) -> &[String] {
        self.only.as_deref().unwrap_or_default()
    }

    pub fn skipped_apis(&self) -> &[String] {
        self.skip.as_deref().unwrap_or_default()
    }

    pub fn includes(&self, api: &str) -> bool {
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

fn load<T: Default + DeserializeOwned>(target_root: &Path) -> Result<T> {
    let path = target_root.join(PATH);
    match std::fs::read(&path) {
        Ok(bytes) => serde_yaml::from_slice(&bytes)
            .with_context(|| format!("invalid regression scope {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn normalize_recording_run_id(recording_run_id: Option<String>) -> Result<Option<String>> {
    let recording_run_id = recording_run_id.filter(|run_id| !run_id.is_empty());
    if let Some(run_id) = &recording_run_id {
        ensure!(
            run_id.len() == 14 && run_id.bytes().all(|byte| byte.is_ascii_digit()),
            "{PATH}: recording_run_id must be a 14-digit existing recording run ID"
        );
    }
    Ok(recording_run_id)
}

pub const GITIGNORE_RULE: &str = "/.traffic-e2e/regression.yaml";
pub const GIT_PATHSPEC: &str = ":(exclude).traffic-e2e/regression.yaml";
pub const TEMPLATE: &str = r#"# Local regression settings are excluded from target fingerprints.
# Set recording_run_id to reuse an existing completed recording.
# recording_run_id: "20260911093000"
max_implementers: 16

# Optional settings for Case workflows.
# only and skip select canonical API inventory routes without HTTP methods.
# only:
#   - "/api/users/*"
# skip: []
# auto_next: false
# retry_failed_only: false
# replay_timing: fast
# replay_interval_cap_ms: 5
"#;

pub fn initialize(target_root: &Path) -> Result<()> {
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
    fn session_regression_accepts_the_generated_template_and_session_settings() {
        let root = tempfile::tempdir().unwrap();
        initialize(root.path()).unwrap();
        let defaults = SessionRegression::load(root.path()).unwrap();
        assert_eq!(defaults.recording_run_id, None);
        assert_eq!(defaults.max_implementers, 16);

        std::fs::write(
            root.path().join(PATH),
            "recording_run_id: \"20261123161021\"\nmax_implementers: 8\n",
        )
        .unwrap();
        let configured = SessionRegression::load(root.path()).unwrap();
        assert_eq!(
            configured.recording_run_id.as_deref(),
            Some("20261123161021")
        );
        assert_eq!(configured.max_implementers, 8);
    }

    #[test]
    fn session_regression_rejects_case_settings_and_out_of_range_capacity() {
        let root = tempfile::tempdir().unwrap();
        initialize(root.path()).unwrap();
        for setting in [
            "only: []",
            "skip: []",
            "auto_next: true",
            "retry_failed_only: true",
            "replay_timing: fast",
            "replay_interval_cap_ms: 0",
            "max_implementers: 0",
            "max_implementers: 17",
        ] {
            std::fs::write(root.path().join(PATH), setting).unwrap();
            let error = SessionRegression::load(root.path()).unwrap_err();
            let (key, _) = setting.split_once(':').unwrap();
            assert!(format!("{error:#}").contains(key), "{setting}: {error:#}");
        }
    }

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
