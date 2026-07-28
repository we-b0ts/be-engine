use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{info, warn};

use super::{BodyCapture, RecorderEvent};
use crate::breeze;
use crate::config::BackgroundDependencyRuleConfig;
use crate::config::background_dependencies::matches_memcached_key_series;
use crate::dependency::DependencyExchangeOutcome;

#[derive(Debug, Default)]
pub(crate) struct BackgroundDependencyMatcher {
    http_rules: Vec<BackgroundDependencyRuleConfig>,
    memcached_by_port: HashMap<u16, Vec<MemcachedRule>>,
    initial_loads: InitialLoads,
}

#[derive(Debug)]
struct MemcachedRule {
    name: String,
    key_start: u32,
    key_end: u32,
    key_separator: u8,
    key_suffix: Vec<u8>,
    initial_load: Arc<InitialLoad>,
}

#[derive(Debug)]
pub(crate) struct BackgroundDependencyMatch {
    rule_name: String,
    initial_load: Option<Arc<InitialLoad>>,
    completed_response: bool,
}

#[derive(Debug)]
struct InitialLoad {
    name: String,
    expected: u64,
    timeout: Duration,
    completed: AtomicU64,
}

#[derive(Debug)]
struct InitialLoads {
    rules: Vec<Arc<InitialLoad>>,
    changed: watch::Sender<u64>,
}

impl Default for InitialLoads {
    fn default() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            rules: Vec::new(),
            changed,
        }
    }
}

impl BackgroundDependencyMatcher {
    pub(crate) fn resolve(rules: &[BackgroundDependencyRuleConfig]) -> Result<Self> {
        Self::resolve_in(rules, Path::new(breeze::SOCKS_DIR))
    }

    fn resolve_in(rules: &[BackgroundDependencyRuleConfig], socks_dir: &Path) -> Result<Self> {
        let mut matcher = Self::default();
        let mut resolved_ports = HashMap::<String, u16>::new();
        for rule in rules {
            match rule {
                BackgroundDependencyRuleConfig::Http { .. } => {
                    matcher.http_rules.push(rule.clone());
                }
                BackgroundDependencyRuleConfig::Memcached {
                    name,
                    breeze_identity,
                    key_start,
                    key_end,
                    key_separator,
                    key_suffix,
                    initial_load_timeout_ms,
                    ..
                } => {
                    let port = match resolved_ports.get(breeze_identity) {
                        Some(port) => *port,
                        None => {
                            let descriptor =
                                breeze::resolve_identity(socks_dir, breeze_identity).with_context(
                                    || {
                                        format!(
                                            "Memcached background dependency rule {name:?} cannot resolve its Breeze resource"
                                        )
                                    },
                                )?;
                            resolved_ports.insert(breeze_identity.clone(), descriptor.port);
                            descriptor.port
                        }
                    };
                    let initial_load = Arc::new(InitialLoad {
                        name: name.clone(),
                        expected: u64::from(*key_end) - u64::from(*key_start) + 1,
                        timeout: Duration::from_millis(*initial_load_timeout_ms),
                        completed: AtomicU64::new(0),
                    });
                    matcher.initial_loads.rules.push(initial_load.clone());
                    matcher
                        .memcached_by_port
                        .entry(port)
                        .or_default()
                        .push(MemcachedRule {
                            name: name.clone(),
                            key_start: *key_start,
                            key_end: *key_end,
                            key_separator: key_separator.as_bytes()[0],
                            key_suffix: key_suffix.as_bytes().to_vec(),
                            initial_load,
                        });
                }
            }
        }
        Ok(matcher)
    }

    pub(crate) fn matching_rule(&self, event: &RecorderEvent) -> Option<BackgroundDependencyMatch> {
        if let RecorderEvent::MemcachedExchange(exchange) = event {
            if !exchange.command.eq_ignore_ascii_case("get") {
                return None;
            }
            let rules = self.memcached_by_port.get(&exchange.target_port)?;
            let key = exchange.key.as_ref().and_then(decode_capture)?;
            return rules.iter().find(|rule| rule.matches(&key)).map(|rule| {
                BackgroundDependencyMatch {
                    rule_name: rule.name.clone(),
                    initial_load: Some(rule.initial_load.clone()),
                    completed_response: exchange.outcome == DependencyExchangeOutcome::Response
                        && !exchange.no_response
                        && exchange.replay_safe,
                }
            });
        }
        self.http_rules
            .iter()
            .find(|rule| rule.matches(event))
            .map(|rule| BackgroundDependencyMatch {
                rule_name: rule.name().to_string(),
                initial_load: None,
                completed_response: false,
            })
    }

    pub(crate) fn record_completed_match(&self, matched: &BackgroundDependencyMatch) {
        if !matched.completed_response {
            return;
        }
        let Some(initial_load) = &matched.initial_load else {
            return;
        };
        let previous =
            initial_load
                .completed
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |completed| {
                    (completed < initial_load.expected).then_some(completed + 1)
                });
        if let Ok(previous) = previous {
            self.initial_loads.changed.send_modify(|version| {
                *version = version.wrapping_add(1);
            });
            if previous + 1 == initial_load.expected {
                info!(
                    rule = %initial_load.name,
                    completed = initial_load.expected,
                    expected = initial_load.expected,
                    "Memcached runtime-state initial load completed"
                );
            }
        }
    }

    pub(crate) fn has_initial_loads(&self) -> bool {
        !self.initial_loads.rules.is_empty()
    }

    pub(crate) async fn wait_for_initial_loads(&self) -> Result<()> {
        if self.initial_loads.rules.is_empty() || self.pending_initial_loads().is_empty() {
            return Ok(());
        }
        let started = Instant::now();
        let mut changed = self.initial_loads.changed.subscribe();
        loop {
            let pending = self.pending_initial_loads();
            if pending.is_empty() {
                return Ok(());
            }
            let elapsed = started.elapsed();
            let Some(remaining) = pending
                .iter()
                .map(|rule| rule.timeout.saturating_sub(elapsed))
                .min()
            else {
                return Ok(());
            };
            if remaining.is_zero() {
                let progress = format_initial_load_progress(&pending);
                warn!(%progress, "Memcached runtime-state initial load timed out");
                bail!(
                    "Memcached runtime-state initial load did not complete after source readiness: {progress}"
                );
            }
            if tokio::time::timeout(remaining, changed.changed())
                .await
                .is_err()
            {
                continue;
            }
        }
    }

    fn pending_initial_loads(&self) -> Vec<&InitialLoad> {
        self.initial_loads
            .rules
            .iter()
            .filter_map(|rule| {
                (rule.completed.load(Ordering::Acquire) < rule.expected).then_some(rule.as_ref())
            })
            .collect()
    }
}

impl BackgroundDependencyMatch {
    pub(crate) fn rule_name(&self) -> &str {
        &self.rule_name
    }
}

impl MemcachedRule {
    fn matches(&self, key: &[u8]) -> bool {
        matches_memcached_key_series(
            key,
            self.key_start,
            self.key_end,
            self.key_separator,
            &self.key_suffix,
        )
    }
}

fn decode_capture(capture: &BodyCapture) -> Option<Vec<u8>> {
    if capture.truncated {
        return None;
    }
    match capture.encoding {
        "utf8" => Some(capture.data.as_bytes().to_vec()),
        "base64" => STANDARD.decode(capture.data.as_bytes()).ok(),
        _ => None,
    }
}

fn format_initial_load_progress(rules: &[&InitialLoad]) -> String {
    rules
        .iter()
        .map(|rule| {
            format!(
                "{}={}/{} timeout_ms={}",
                rule.name,
                rule.completed.load(Ordering::Acquire),
                rule.expected,
                rule.timeout.as_millis()
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::DependencyExchangeOutcome;
    use crate::config::BackgroundDependencyResponseRole;
    use crate::recorder::MemcachedExchangeEvent;

    fn memcached_rule_with(
        identity: String,
        key_end: u32,
        initial_load_timeout_ms: u64,
    ) -> BackgroundDependencyRuleConfig {
        BackgroundDependencyRuleConfig::Memcached {
            name: "planet-video-cache-warm".to_string(),
            breeze_identity: identity,
            command: "get".to_string(),
            key_start: 0,
            key_end,
            key_separator: ".".to_string(),
            key_suffix: "pl_video".to_string(),
            initial_load_timeout_ms,
            response_role: BackgroundDependencyResponseRole::RuntimeState,
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "TopUserServiceImpl.java:691 scheduled local cache warm".to_string(),
        }
    }

    fn memcached_rule(identity: String) -> BackgroundDependencyRuleConfig {
        memcached_rule_with(identity, 4095, 30_000)
    }

    fn event(port: u16, command: &str, key: &[u8]) -> RecorderEvent {
        RecorderEvent::MemcachedExchange(MemcachedExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            sequence: 1,
            timestamp: Utc::now(),
            client_addr: None,
            target_host: "breeze.recording".to_string(),
            target_port: port,
            target_addr: format!("breeze.recording:{port}"),
            upstream_addr: format!("127.0.0.1:{port}"),
            wire_protocol: "binary".to_string(),
            command: command.to_string(),
            opcode: Some(0),
            opaque: Some(1),
            key: Some(crate::recorder::capture_body(key, key.len())),
            args: Vec::new(),
            value: None,
            extras: None,
            cas: None,
            noreply: false,
            quiet: false,
            response_status: "0".to_string(),
            response_frames: Vec::new(),
            no_response: false,
            outcome: DependencyExchangeOutcome::Response,
            duration_ms: 1,
            replay_safe: true,
            parse_warnings: Vec::new(),
        })
    }

    #[test]
    fn resolves_port_first_then_matches_exact_get_key_series() {
        let temp = tempfile::tempdir().unwrap();
        let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
        std::fs::write(temp.path().join(filename), "").unwrap();
        let identity = filename.replace(":9448", "");
        let matcher =
            BackgroundDependencyMatcher::resolve_in(&[memcached_rule(identity)], temp.path())
                .unwrap();

        assert_eq!(
            matcher
                .matching_rule(&event(9448, "get", b"0.pl_video"))
                .map(|matched| matched.rule_name().to_string()),
            Some("planet-video-cache-warm".to_string())
        );
        assert_eq!(
            matcher
                .matching_rule(&event(9448, "GET", b"4095.pl_video"))
                .map(|matched| matched.rule_name().to_string()),
            Some("planet-video-cache-warm".to_string())
        );
        assert!(
            matcher
                .matching_rule(&event(9449, "get", b"0.pl_video"))
                .is_none()
        );
        assert!(
            matcher
                .matching_rule(&event(9448, "set", b"0.pl_video"))
                .is_none()
        );
        assert!(
            matcher
                .matching_rule(&event(9448, "get", b"4096.pl_video"))
                .is_none()
        );
        assert!(
            matcher
                .matching_rule(&event(9448, "get", b"00.pl_video"))
                .is_none()
        );
        assert!(
            matcher
                .matching_rule(&event(9448, "get", b"0.other"))
                .is_none()
        );
    }

    #[tokio::test]
    async fn initial_load_completion_uses_matching_exchange_count() {
        let temp = tempfile::tempdir().unwrap();
        let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
        std::fs::write(temp.path().join(filename), "").unwrap();
        let identity = filename.replace(":9448", "");
        let matcher = BackgroundDependencyMatcher::resolve_in(
            &[memcached_rule_with(identity, 2, 50)],
            temp.path(),
        )
        .unwrap();

        for _ in 0..3 {
            let matched = matcher
                .matching_rule(&event(9448, "get", b"0.pl_video"))
                .unwrap();
            matcher.record_completed_match(&matched);
        }

        matcher.wait_for_initial_loads().await.unwrap();
    }

    #[tokio::test]
    async fn initial_load_timeout_reports_matching_exchange_progress() {
        let temp = tempfile::tempdir().unwrap();
        let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
        std::fs::write(temp.path().join(filename), "").unwrap();
        let identity = filename.replace(":9448", "");
        let matcher = BackgroundDependencyMatcher::resolve_in(
            &[memcached_rule_with(identity, 1, 5)],
            temp.path(),
        )
        .unwrap();
        let matched = matcher
            .matching_rule(&event(9448, "get", b"0.pl_video"))
            .unwrap();
        matcher.record_completed_match(&matched);

        let error = matcher.wait_for_initial_loads().await.unwrap_err();
        assert!(error.to_string().contains("planet-video-cache-warm=1/2"));
    }
}
