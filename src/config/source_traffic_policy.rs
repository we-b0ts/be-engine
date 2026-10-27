use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::process_owned_dependencies::{self, BackgroundDependencyRuleConfig};
use super::{AppConfig, DnsBypassStrategyConfig};

pub(crate) mod http_response;

pub const SOURCE_TRAFFIC_POLICY_VERSION: u32 = 2;

#[cfg(test)]
const MANAGED_HEADER: &str =
    "# Managed by the backend-rewrite coordinator. Do not edit manually.\n";

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceTrafficPolicyConfig {
    pub version: u32,
    #[serde(default)]
    pub http: SourceTrafficHttpPolicyConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "http_response")]
    pub http_response_rewrite: Vec<super::HttpResponseRewriteRuleConfig>,
    #[serde(default)]
    pub breeze_capture: Vec<SourceTrafficBreezeCaptureConfig>,
    #[serde(default)]
    pub process_owned_dependencies: Vec<BackgroundDependencyRuleConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub async_api: BTreeMap<String, crate::policy::AsyncApiRules>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceTrafficHttpPolicyConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_revision: String,
    #[serde(default)]
    pub case_path_patterns: Vec<String>,
    #[serde(default)]
    pub allowed_unused_http_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceTrafficBreezeCaptureConfig {
    pub snapshot_dir: PathBuf,
    #[serde(default)]
    pub capture_resources: Vec<String>,
}

impl SourceTrafficPolicyConfig {
    #[cfg(test)]
    pub fn empty() -> Self {
        Self {
            version: SOURCE_TRAFFIC_POLICY_VERSION,
            http: SourceTrafficHttpPolicyConfig::default(),
            http_response_rewrite: Vec::new(),
            breeze_capture: Vec::new(),
            process_owned_dependencies: Vec::new(),
            async_api: BTreeMap::new(),
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::load_with_fingerprints(path.as_ref())?.0)
    }

    pub(crate) fn load_with_fingerprints(
        path: &Path,
    ) -> Result<(Self, crate::policy::PolicyFingerprints)> {
        require_regular_file(path)?;
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read unified traffic policy {}", path.display()))?;
        super::native_policy::parse_source_with_fingerprints(&raw)
            .with_context(|| format!("failed to parse unified traffic policy {}", path.display()))
    }

    pub fn parse(raw: &str, path: &Path) -> Result<Self> {
        let config = super::native_policy::parse_source_policy(raw).with_context(|| {
            format!("failed to parse unified traffic policy {}", path.display())
        })?;
        config
            .validate()
            .with_context(|| format!("invalid source traffic policy {}", path.display()))?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == SOURCE_TRAFFIC_POLICY_VERSION,
            "unsupported source traffic policy version {}; expected {}",
            self.version,
            SOURCE_TRAFFIC_POLICY_VERSION
        );
        crate::policy::compile_async_api(&self.async_api)?;
        let mut snapshots = BTreeSet::new();
        for capture in &self.breeze_capture {
            ensure!(
                !capture.snapshot_dir.as_os_str().is_empty()
                    && snapshots.insert(&capture.snapshot_dir),
                "coordinator Breeze capture snapshot_dir values must be non-empty and unique"
            );
        }
        super::HttpResponseRewriteConfig {
            enabled: true,
            rules: self.http_response_rewrite.clone(),
        }
        .validate()?;
        process_owned_dependencies::validate(&self.process_owned_dependencies)
    }

    #[cfg(test)]
    pub fn render(&self) -> Result<String> {
        self.validate()?;
        let mut output = String::from(MANAGED_HEADER);
        output.push_str(&super::native_policy::render_initial(self)?);
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
                    "source traffic Breeze capture {:?} has no matching recorder strategy",
                    overlay.snapshot_dir
                )
            })?;
            ensure!(
                matches.next().is_none(),
                "source traffic Breeze capture {:?} matches multiple recorder strategies",
                overlay.snapshot_dir
            );
            let DnsBypassStrategyConfig::Breeze {
                capture_resources, ..
            } = strategy;
            *capture_resources = overlay.capture_resources.clone();
        }
        config
            .http_response_rewrite
            .rules
            .extend(self.http_response_rewrite.iter().cloned());
        config.http_response_rewrite.validate()?;
        config.process_owned_dependencies = self.process_owned_dependencies.clone();
        config.async_api = self.async_api.clone();
        Ok(())
    }
}

fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect source traffic policy {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "source traffic policy must be a regular file and not a symlink: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_round_trips_with_managed_header() {
        let rendered = SourceTrafficPolicyConfig::empty().render().unwrap();
        assert!(rendered.starts_with(MANAGED_HEADER));
        let parsed =
            SourceTrafficPolicyConfig::parse(&rendered, Path::new("source-traffic-policy.yaml"))
                .unwrap();
        assert_eq!(parsed, SourceTrafficPolicyConfig::empty());
    }

    #[test]
    fn initial_policy_has_no_implicit_service_ownership() {
        let rules = SourceTrafficPolicyConfig::empty();
        assert_eq!(rules.http, SourceTrafficHttpPolicyConfig::default());
        assert!(rules.process_owned_dependencies.is_empty());
        rules.validate().unwrap();
    }

    #[test]
    fn old_source_file_formats_are_rejected() {
        for raw in ["version: 1\nhttp: []\n", "version: 2\nhttp: {}\n"] {
            assert!(SourceTrafficPolicyConfig::parse(raw, Path::new("policy.yaml")).is_err());
        }
    }
}
