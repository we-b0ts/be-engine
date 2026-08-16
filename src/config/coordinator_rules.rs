use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::process_owned_dependencies::{self, BackgroundDependencyRuleConfig};
use super::{AppConfig, DnsBypassStrategyConfig};

pub const COORDINATOR_RULES_VERSION: u32 = 2;
pub const COORDINATOR_RULES_FILE: &str = "coordinator-rules.yaml";

const MANAGED_HEADER: &str =
    "# Managed by the backend-rewrite coordinator. Do not edit manually.\n";

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorRulesConfig {
    pub version: u32,
    #[serde(default)]
    pub http: CoordinatorHttpConfig,
    #[serde(default)]
    pub breeze_capture: Vec<CoordinatorBreezeCaptureConfig>,
    #[serde(default)]
    pub process_owned_dependencies: Vec<BackgroundDependencyRuleConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorHttpConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_revision: String,
    #[serde(default)]
    pub case_path_patterns: Vec<String>,
    #[serde(default)]
    pub allowed_unused_http_hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CoordinatorRulesVersion {
    version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCoordinatorRulesConfig {
    version: u32,
    #[serde(default)]
    http: Vec<LegacyCoordinatorHttpRuleConfig>,
    #[serde(default)]
    breeze_capture: Vec<CoordinatorBreezeCaptureConfig>,
    #[serde(default)]
    process_owned_dependencies: Vec<BackgroundDependencyRuleConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCoordinatorHttpRuleConfig {
    #[serde(rename = "name")]
    _name: String,
    #[serde(default)]
    source_revision: String,
    #[serde(default)]
    case_path_patterns: Vec<String>,
    #[serde(default)]
    allowed_unused_http_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorBreezeCaptureConfig {
    pub snapshot_dir: PathBuf,
    #[serde(default)]
    pub capture_resources: Vec<String>,
}

impl CoordinatorRulesConfig {
    #[cfg(test)]
    pub fn empty() -> Self {
        Self {
            version: COORDINATOR_RULES_VERSION,
            http: CoordinatorHttpConfig::default(),
            breeze_capture: Vec::new(),
            process_owned_dependencies: Vec::new(),
        }
    }

    pub fn repository_defaults() -> Self {
        Self {
            version: COORDINATOR_RULES_VERSION,
            http: CoordinatorHttpConfig::default(),
            breeze_capture: Vec::new(),
            process_owned_dependencies: vec![BackgroundDependencyRuleConfig::Http {
                name: "breeze_vintage".to_string(),
                authorities: vec![
                    "config.api.demo.test".to_string(),
                    "static.config.api.demo.test".to_string(),
                    "register.kailash.demo.test".to_string(),
                ],
                methods: vec!["GET".to_string()],
                path_prefixes: vec![
                    "/1/config/service".to_string(),
                    "/naming/service".to_string(),
                ],
                source_revision: String::new(),
                source_evidence: "traffic-e2e system default: Weibo Breeze Vintage configuration and naming refresh are process-owned".to_string(),
            }],
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        require_regular_file(path)?;
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read coordinator rules {}", path.display()))?;
        Self::parse(&raw, path)
    }

    pub fn parse(raw: &str, path: &Path) -> Result<Self> {
        let version: CoordinatorRulesVersion = serde_yaml::from_str(raw)
            .with_context(|| format!("failed to parse coordinator rules {}", path.display()))?;
        let config = match version.version {
            1 => {
                let legacy: LegacyCoordinatorRulesConfig =
                    serde_yaml::from_str(raw).with_context(|| {
                        format!("failed to parse coordinator rules {}", path.display())
                    })?;
                Self::from_legacy(legacy)
            }
            COORDINATOR_RULES_VERSION => serde_yaml::from_str(raw)
                .with_context(|| format!("failed to parse coordinator rules {}", path.display()))?,
            unsupported => anyhow::bail!(
                "unsupported coordinator rules version {unsupported}; expected 1 or {COORDINATOR_RULES_VERSION}"
            ),
        };
        config
            .validate()
            .with_context(|| format!("invalid coordinator rules {}", path.display()))?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == COORDINATOR_RULES_VERSION,
            "unsupported coordinator rules version {}; expected {}",
            self.version,
            COORDINATOR_RULES_VERSION
        );
        let mut snapshots = BTreeSet::new();
        for capture in &self.breeze_capture {
            ensure!(
                !capture.snapshot_dir.as_os_str().is_empty()
                    && snapshots.insert(&capture.snapshot_dir),
                "coordinator Breeze capture snapshot_dir values must be non-empty and unique"
            );
        }
        process_owned_dependencies::validate(&self.process_owned_dependencies)
    }

    pub fn render(&self) -> Result<String> {
        self.validate()?;
        let mut output = String::from(MANAGED_HEADER);
        output.push_str(&serde_yaml::to_string(self)?);
        if !output.ends_with('\n') {
            output.push('\n');
        }
        Ok(output)
    }

    pub fn apply_to(&self, config: &mut AppConfig) -> Result<()> {
        config.http_gateway.case_path_patterns = self.http.case_path_patterns.clone();
        config.http_gateway.allowed_unused_http_hosts = self.http.allowed_unused_http_hosts.clone();
        for overlay in &self.breeze_capture {
            let mut matches = config
                .dns_mock
                .bypass_strategies
                .iter_mut()
                .filter(|strategy| match strategy {
                    DnsBypassStrategyConfig::Breeze { snapshot_dir, .. } => {
                        snapshot_dir == &overlay.snapshot_dir
                    }
                });
            let strategy = matches.next().with_context(|| {
                format!(
                    "coordinator Breeze capture {:?} has no matching recorder strategy",
                    overlay.snapshot_dir
                )
            })?;
            ensure!(
                matches.next().is_none(),
                "coordinator Breeze capture {:?} matches multiple recorder strategies",
                overlay.snapshot_dir
            );
            let DnsBypassStrategyConfig::Breeze {
                capture_resources, ..
            } = strategy;
            *capture_resources = overlay.capture_resources.clone();
        }
        config.process_owned_dependencies = self.process_owned_dependencies.clone();
        Ok(())
    }

    fn from_legacy(legacy: LegacyCoordinatorRulesConfig) -> Self {
        debug_assert_eq!(legacy.version, 1);
        let source_revisions = legacy
            .http
            .iter()
            .map(|rule| rule.source_revision.as_str())
            .filter(|revision| !revision.is_empty())
            .collect::<BTreeSet<_>>();
        let source_revision = if source_revisions.len() == 1 {
            source_revisions
                .into_iter()
                .next()
                .unwrap_or_default()
                .to_string()
        } else {
            String::new()
        };
        let case_path_patterns = legacy
            .http
            .iter()
            .flat_map(|rule| rule.case_path_patterns.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let allowed_unused_http_hosts = legacy
            .http
            .iter()
            .flat_map(|rule| rule.allowed_unused_http_hosts.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self {
            version: COORDINATOR_RULES_VERSION,
            http: CoordinatorHttpConfig {
                source_revision,
                case_path_patterns,
                allowed_unused_http_hosts,
            },
            breeze_capture: legacy.breeze_capture,
            process_owned_dependencies: legacy.process_owned_dependencies,
        }
    }
}

pub fn resolve_from_project_config(project_config: &Path, relative: &Path) -> Result<PathBuf> {
    ensure!(
        !relative.as_os_str().is_empty() && relative.is_relative(),
        "project.recording.coordinator_rules must be a non-empty path relative to project.yaml"
    );
    ensure!(
        relative.components().all(|component| matches!(
            component,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        )),
        "project.recording.coordinator_rules must stay within the project configuration directory"
    );
    let parent = project_config
        .parent()
        .context("project config has no parent directory")?;
    Ok(parent.join(relative))
}

fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect coordinator rules {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "coordinator rules must be a regular file and not a symlink: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rules_round_trip_with_managed_header() {
        let rendered = CoordinatorRulesConfig::empty().render().unwrap();
        assert!(rendered.starts_with(MANAGED_HEADER));
        let parsed =
            CoordinatorRulesConfig::parse(&rendered, Path::new("coordinator-rules.yaml")).unwrap();
        assert_eq!(parsed, CoordinatorRulesConfig::empty());
    }

    #[test]
    fn rejects_paths_outside_project_config_directory() {
        let error = resolve_from_project_config(
            Path::new(".traffic-e2e/project.yaml"),
            Path::new("../rules.yaml"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("must stay within"));
    }

    #[test]
    fn repository_defaults_use_global_http_policy() {
        let rules = CoordinatorRulesConfig::repository_defaults();
        assert_eq!(rules.http, CoordinatorHttpConfig::default());
        rules.validate().unwrap();
    }

    #[test]
    fn legacy_named_http_rules_merge_into_global_policy() {
        let parsed = CoordinatorRulesConfig::parse(
            "version: 1\nhttp:\n- name: first\n  source_revision: abc\n  case_path_patterns: [/a/*]\n  allowed_unused_http_hosts: [a.example]\n- name: second\n  source_revision: abc\n  case_path_patterns: [/b/*]\n  allowed_unused_http_hosts: [b.example]\nbreeze_capture: []\nprocess_owned_dependencies: []\n",
            Path::new("coordinator-rules.yaml"),
        )
        .unwrap();

        assert_eq!(parsed.version, COORDINATOR_RULES_VERSION);
        assert_eq!(parsed.http.source_revision, "abc");
        assert_eq!(parsed.http.case_path_patterns, ["/a/*", "/b/*"]);
        assert_eq!(
            parsed.http.allowed_unused_http_hosts,
            ["a.example", "b.example"]
        );
    }
}
