use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use tracing::{info, trace};

use crate::{DnsBypassStrategyConfig, DnsMockConfig};

#[derive(Debug, Clone, Default)]
pub(crate) struct DomainMatcher {
    exact: HashSet<String>,
    suffixes: Vec<String>,
    wildcards: Vec<String>,
}

impl DomainMatcher {
    pub(crate) fn from_config(config: &DnsMockConfig) -> Result<Self> {
        let mut matcher = Self::from_patterns(&config.bypass_domains);

        for strategy in &config.bypass_strategies {
            match strategy {
                DnsBypassStrategyConfig::Breeze { snapshot_dir } => {
                    let snapshot = load_breeze_snapshot(snapshot_dir)?;
                    let loaded_domains = snapshot.domains.len();
                    let loaded_files = snapshot.files;
                    trace!(
                        snapshot_dir = %snapshot_dir.display(),
                        domains = ?snapshot.domains,
                        "loaded Breeze bypass domains"
                    );
                    matcher.exact.extend(snapshot.domains);
                    info!(
                        strategy = "breeze",
                        snapshot_dir = %snapshot_dir.display(),
                        files = loaded_files,
                        domains = loaded_domains,
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

    pub(crate) fn from_patterns(patterns: &[String]) -> Self {
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

    pub(crate) fn matches(&self, domain: &str) -> bool {
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

    pub(crate) fn exact_count(&self) -> usize {
        self.exact.len()
    }

    pub(crate) fn suffix_count(&self) -> usize {
        self.suffixes.len()
    }

    pub(crate) fn wildcard_count(&self) -> usize {
        self.wildcards.len()
    }
}

struct BreezeSnapshot {
    files: usize,
    domains: HashSet<String>,
}

fn load_breeze_snapshot(snapshot_dir: &Path) -> Result<BreezeSnapshot> {
    ensure!(
        snapshot_dir.is_dir(),
        "Breeze bypass snapshot directory does not exist or is not a directory: {}",
        snapshot_dir.display()
    );

    let files = snapshot_files(snapshot_dir)?;
    ensure!(
        !files.is_empty(),
        "Breeze bypass snapshot directory contains no regular files: {}",
        snapshot_dir.display()
    );

    let mut domains = HashSet::new();
    for path in &files {
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read Breeze snapshot {}", path.display()))?;
        extract_backend_domains(&source, &mut domains);
    }
    ensure!(
        !domains.is_empty(),
        "Breeze bypass snapshot contains no hostname:port backends: {}",
        snapshot_dir.display()
    );

    Ok(BreezeSnapshot {
        files: files.len(),
        domains,
    })
}

fn snapshot_files(snapshot_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![snapshot_dir.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).with_context(|| {
            format!(
                "failed to list Breeze snapshot directory {}",
                directory.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "failed to read an entry under Breeze snapshot directory {}",
                    directory.display()
                )
            })?;
            let file_type = entry.file_type().with_context(|| {
                format!(
                    "failed to inspect Breeze snapshot {}",
                    entry.path().display()
                )
            })?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn extract_backend_domains(source: &str, domains: &mut HashSet<String>) {
    for token in source.split(|character: char| {
        character.is_ascii_whitespace()
            || matches!(character, ',' | '[' | ']' | '{' | '}' | '(' | ')' | ';')
    }) {
        let token =
            token.trim_matches(|character: char| matches!(character, '-' | '\'' | '"' | '`'));
        let Some((host, port)) = token.rsplit_once(':') else {
            continue;
        };
        if port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
            continue;
        }
        let host = normalize_domain(host);
        if is_hostname(&host) {
            domains.insert(host);
        }
    }
}

fn is_hostname(value: &str) -> bool {
    if value.len() > 253 || !value.contains('.') || value.parse::<IpAddr>().is_ok() {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

pub(super) fn normalize_domain(domain: &str) -> String {
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
    use super::*;

    #[test]
    fn matches_exact_suffix_and_wildcard_patterns() {
        let matcher = DomainMatcher::from_patterns(&[
            "preview-wss-wegent.intra.demo.test".to_string(),
            ".internal.example.com".to_string(),
            "*.dingtalk.com".to_string(),
            "api?.service.example.com".to_string(),
        ]);

        assert!(matcher.matches("preview-wss-wegent.intra.demo.test"));
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
            }],
            ..DnsMockConfig::default()
        };

        let error = DomainMatcher::from_config(&config).unwrap_err();

        assert!(error.to_string().contains("no hostname:port backends"));
    }
}
