use std::collections::HashSet;

use anyhow::{Result, ensure};
use tracing::{info, trace};

use crate::breeze::snapshot::Snapshot;
use crate::{DnsBypassStrategyConfig, DnsMockConfig};

#[derive(Debug, Clone, Default)]
pub struct DomainMatcher {
    exact: HashSet<String>,
    suffixes: Vec<String>,
    wildcards: Vec<String>,
}

impl DomainMatcher {
    pub fn from_config(config: &DnsMockConfig) -> Result<Self> {
        let mut matcher = Self::from_patterns(&config.bypass_domains);

        for strategy in &config.bypass_strategies {
            match strategy {
                DnsBypassStrategyConfig::Breeze {
                    snapshot_dir,
                    capture_resources,
                } => {
                    let snapshot = Snapshot::load(snapshot_dir)?;
                    let mut bypass_domains = snapshot.domains();
                    ensure!(
                        !bypass_domains.is_empty(),
                        "Breeze bypass snapshot contains no hostname:port backends: {}",
                        snapshot_dir.display()
                    );
                    let mut captured_domains = HashSet::new();
                    for selector in capture_resources {
                        let resource = snapshot.resolve(selector)?;
                        ensure!(
                            !resource.domains.is_empty(),
                            "Breeze capture resource {:?} contains no hostname backend; IP literals are not part of DNS bypass",
                            resource.identity
                        );
                        captured_domains.extend(resource.domains.iter().cloned());
                    }
                    bypass_domains.retain(|domain| !captured_domains.contains(domain));
                    let loaded_domains = bypass_domains.len();
                    let loaded_files = snapshot.file_count();
                    trace!(
                        snapshot_dir = %snapshot_dir.display(),
                        domains = ?bypass_domains,
                        "loaded Breeze bypass domains"
                    );
                    matcher.exact.extend(bypass_domains);
                    info!(
                        strategy = "breeze",
                        snapshot_dir = %snapshot_dir.display(),
                        files = loaded_files,
                        domains = loaded_domains,
                        capture_resources = capture_resources.len(),
                        captured_domains = captured_domains.len(),
                        "DNS bypass strategy loaded"
                    );
                }
            }
        }

        matcher.suffixes.sort();
        matcher.suffixes.dedup();
        matcher.wildcards.sort();
        matcher.wildcards.dedup();
        Ok(matcher)
    }

    pub fn from_patterns(patterns: &[String]) -> Self {
        let mut matcher = Self::default();
        for pattern in patterns {
            let pattern = normalize_domain(pattern);
            if pattern.is_empty() {
                continue;
            }
            if pattern.contains('*') || pattern.contains('?') {
                matcher.wildcards.push(pattern);
            } else if let Some(suffix) = pattern.strip_prefix('.') {
                if !suffix.is_empty() {
                    matcher.suffixes.push(suffix.to_string());
                }
            } else {
                matcher.exact.insert(pattern);
            }
        }
        matcher
    }

    pub fn matches(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.exact.contains(&domain)
            || self.suffixes.iter().any(|suffix| {
                domain == *suffix
                    || domain
                        .strip_suffix(suffix)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            })
            || self
                .wildcards
                .iter()
                .any(|pattern| wildcard_matches(pattern, &domain))
    }

    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }

    pub fn suffix_count(&self) -> usize {
        self.suffixes.len()
    }

    pub fn wildcard_count(&self) -> usize {
        self.wildcards.len()
    }
}

pub fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;

    for pattern_char in pattern {
        let mut current = vec![false; value.len() + 1];
        match *pattern_char {
            b'*' => {
                current[0] = previous[0];
                for idx in 1..=value.len() {
                    current[idx] = previous[idx] || current[idx - 1];
                }
            }
            b'?' => current[1..=value.len()].copy_from_slice(&previous[..value.len()]),
            literal => {
                for idx in 1..=value.len() {
                    current[idx] = previous[idx - 1] && value[idx - 1] == literal;
                }
            }
        }
        previous = current;
    }

    previous[value.len()]
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn matches_exact_suffix_and_wildcard_patterns() {
        let matcher = DomainMatcher::from_patterns(&[
            "preview-wss.internal.example.test".to_string(),
            ".internal.example.com".to_string(),
            "*.dingtalk.com".to_string(),
            "api?.service.example.com".to_string(),
        ]);

        assert!(matcher.matches("preview-wss.internal.example.test"));
        assert!(matcher.matches("api.internal.example.com"));
        assert!(matcher.matches("internal.example.com"));
        assert!(!matcher.matches("notinternal.example.com"));
        assert!(matcher.matches("open.dingtalk.com"));
        assert!(matcher.matches("a.b.dingtalk.com"));
        assert!(!matcher.matches("dingtalk.com"));
        assert!(matcher.matches("api1.service.example.com"));
        assert!(!matcher.matches("api12.service.example.com"));
    }

    #[test]
    fn breeze_snapshot_extracts_only_hostname_port_backends() {
        let directory = tempfile::tempdir().unwrap();
        let snapshot = directory.path().join("status.content.kv");
        fs::write(
            &snapshot,
            "status.content.kv\nbackends:\n- RM1.EOS.GRID.sample.test:9028,rs1.hebe.grid.sample.test:9028\nresource.with.dots\n10.0.0.1:6379\n",
        )
        .unwrap();
        let config = DnsMockConfig {
            bypass_strategies: vec![DnsBypassStrategyConfig::Breeze {
                snapshot_dir: directory.path().to_path_buf(),
                capture_resources: Vec::new(),
            }],
            ..DnsMockConfig::default()
        };

        let matcher = DomainMatcher::from_config(&config).unwrap();

        assert_eq!(matcher.exact_count(), 2);
        assert!(matcher.matches("rm1.eos.grid.sample.test"));
        assert!(matcher.matches("RS1.HEBE.GRID.sample.test."));
        assert!(!matcher.matches("resource.with.dots"));
        assert!(!matcher.matches("10.0.0.1"));
    }

    #[test]
    fn breeze_strategy_fails_when_snapshot_has_no_backends() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("empty"), "status.content.kv\n").unwrap();
        let config = DnsMockConfig {
            bypass_strategies: vec![DnsBypassStrategyConfig::Breeze {
                snapshot_dir: directory.path().to_path_buf(),
                capture_resources: Vec::new(),
            }],
            ..DnsMockConfig::default()
        };

        let error = DomainMatcher::from_config(&config).unwrap_err();

        assert!(error.to_string().contains("no hostname:port backends"));
    }

    #[test]
    fn breeze_capture_resource_removes_its_domains_from_bypass() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("usercounter-descriptor"),
            "123\nusercounter\nbackends:\n- counter.example.com:7917,shared.example.com:7917\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("other-descriptor"),
            "123\nother\nbackends:\n- other.example.com:6379,shared.example.com:6379\n",
        )
        .unwrap();
        let config = DnsMockConfig {
            bypass_strategies: vec![DnsBypassStrategyConfig::Breeze {
                snapshot_dir: directory.path().to_path_buf(),
                capture_resources: vec!["usercounter-descriptor".to_string()],
            }],
            ..DnsMockConfig::default()
        };

        let matcher = DomainMatcher::from_config(&config).unwrap();

        assert!(!matcher.matches("counter.example.com"));
        assert!(!matcher.matches("shared.example.com"));
        assert!(matcher.matches("other.example.com"));
    }
}
