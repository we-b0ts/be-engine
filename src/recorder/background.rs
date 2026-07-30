use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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

const INITIAL_LOAD_PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(crate) struct BackgroundDependencyMatcher {
    independent_rules: Vec<BackgroundDependencyRuleConfig>,
    socks_dir: PathBuf,
    memcached: Mutex<MemcachedRules>,
    initial_loads: InitialLoads,
}

#[derive(Debug, Default)]
struct MemcachedRules {
    by_port: HashMap<u16, Vec<MemcachedRule>>,
    pending_by_identity: HashMap<String, Vec<MemcachedRule>>,
    ignored_ports: HashSet<u16>,
    last_resolution_error: Option<String>,
}

#[derive(Debug, Clone)]
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
    pub(crate) fn from_rules(rules: &[BackgroundDependencyRuleConfig]) -> Result<Self> {
        Self::from_rules_in(rules, Path::new(breeze::SOCKS_DIR))
    }

    fn from_rules_in(rules: &[BackgroundDependencyRuleConfig], socks_dir: &Path) -> Result<Self> {
        let mut independent_rules = Vec::new();
        let mut memcached = MemcachedRules::default();
        let mut initial_loads = InitialLoads::default();
        for rule in rules {
            match rule {
                BackgroundDependencyRuleConfig::Http { .. }
                | BackgroundDependencyRuleConfig::Motan { .. } => {
                    independent_rules.push(rule.clone());
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
                    let initial_load = Arc::new(InitialLoad {
                        name: name.clone(),
                        expected: u64::from(*key_end) - u64::from(*key_start) + 1,
                        timeout: Duration::from_millis(*initial_load_timeout_ms),
                        completed: AtomicU64::new(0),
                    });
                    initial_loads.rules.push(initial_load.clone());
                    memcached
                        .pending_by_identity
                        .entry(breeze_identity.clone())
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

        let matcher = Self {
            independent_rules,
            socks_dir: socks_dir.to_path_buf(),
            memcached: Mutex::new(memcached),
            initial_loads,
        };
        matcher.refresh_pending_resources()?;
        let pending = matcher.pending_resource_summary();
        if !pending.is_empty() {
            info!(
                resources = %pending,
                directory = %matcher.socks_dir.display(),
                "Memcached background rules are waiting for source-registered Breeze descriptors"
            );
        }
        Ok(matcher)
    }

    pub(crate) fn matching_rule(&self, event: &RecorderEvent) -> Option<BackgroundDependencyMatch> {
        if let RecorderEvent::MemcachedExchange(exchange) = event {
            if !exchange.command.eq_ignore_ascii_case("get") {
                return None;
            }
            let key = exchange.key.as_ref().and_then(decode_capture)?;
            let port_is_resolved = {
                let rules = self.memcached.lock().expect("background rules poisoned");
                if rules.ignored_ports.contains(&exchange.target_port) {
                    return None;
                }
                if let Some(matched) =
                    match_memcached_rule(&rules, exchange.target_port, &key, exchange)
                {
                    return Some(matched);
                }
                rules.by_port.contains_key(&exchange.target_port)
            };
            if port_is_resolved {
                return None;
            }
            let refreshed = self.refresh_pending_resources().is_ok();
            let mut rules = self.memcached.lock().expect("background rules poisoned");
            let matched = match_memcached_rule(&rules, exchange.target_port, &key, exchange);
            if refreshed && matched.is_none() && !rules.by_port.contains_key(&exchange.target_port)
            {
                rules.ignored_ports.insert(exchange.target_port);
            }
            return matched;
        }
        self.independent_rules
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

    pub(crate) fn ensure_resources_resolved(&self) -> Result<()> {
        self.refresh_pending_resources()?;
        let pending = self.pending_resource_summary();
        if pending.is_empty() {
            return Ok(());
        }
        bail!(
            "source reached HTTP readiness without registering configured Breeze resources: {pending}"
        )
    }

    pub(crate) async fn wait_for_initial_loads(&self) {
        if self.initial_loads.rules.is_empty() || self.pending_initial_loads().is_empty() {
            return;
        }
        let _ = self.refresh_pending_resources();
        let started = Instant::now();
        let mut next_progress_log = started + INITIAL_LOAD_PROGRESS_LOG_INTERVAL;
        let mut changed = self.initial_loads.changed.subscribe();
        let pending = self.pending_initial_loads();
        let progress = format_initial_load_progress(&pending);
        let pending_resources = self.pending_resource_summary();
        info!(
            %progress,
            %pending_resources,
            progress_interval_ms = INITIAL_LOAD_PROGRESS_LOG_INTERVAL.as_millis(),
            "Memcached runtime-state initial load observation started"
        );
        loop {
            let pending = self.pending_initial_loads();
            if pending.is_empty() {
                return;
            }
            let elapsed = started.elapsed();
            let Some(remaining) = pending
                .iter()
                .map(|rule| rule.timeout.saturating_sub(elapsed))
                .min()
            else {
                return;
            };
            if remaining.is_zero() {
                let progress = format_initial_load_progress(&pending);
                let pending_resources = self.pending_resource_summary();
                warn!(
                    %progress,
                    %pending_resources,
                    "Memcached runtime-state initial load observation window elapsed; continuing recording"
                );
                return;
            }
            let until_progress_log = next_progress_log.saturating_duration_since(Instant::now());
            let wait = remaining.min(until_progress_log);
            if tokio::time::timeout(wait, changed.changed()).await.is_err() {
                let now = Instant::now();
                if now >= next_progress_log {
                    let _ = self.refresh_pending_resources();
                    let pending = self.pending_initial_loads();
                    if pending.is_empty() {
                        return;
                    }
                    let elapsed = started.elapsed();
                    let remaining_ms = pending
                        .iter()
                        .map(|rule| rule.timeout.saturating_sub(elapsed))
                        .min()
                        .unwrap_or_default()
                        .as_millis();
                    let progress = format_initial_load_progress(&pending);
                    let pending_resources = self.pending_resource_summary();
                    info!(
                        %progress,
                        %pending_resources,
                        remaining_ms,
                        "Memcached runtime-state initial load observation is still waiting"
                    );
                    next_progress_log = now + INITIAL_LOAD_PROGRESS_LOG_INTERVAL;
                }
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

    fn refresh_pending_resources(&self) -> Result<()> {
        let result = self.try_refresh_pending_resources();
        let mut rules = self.memcached.lock().expect("background rules poisoned");
        match &result {
            Ok(()) => rules.last_resolution_error = None,
            Err(error) => {
                let message = format!("{error:#}");
                if rules.last_resolution_error.as_deref() != Some(&message) {
                    warn!(
                        error = %error,
                        directory = %self.socks_dir.display(),
                        "Memcached background rule Breeze descriptor refresh failed"
                    );
                    rules.last_resolution_error = Some(message);
                }
            }
        }
        result
    }

    fn try_refresh_pending_resources(&self) -> Result<()> {
        let identities = {
            let rules = self.memcached.lock().expect("background rules poisoned");
            rules
                .pending_by_identity
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut resolved = Vec::new();
        for identity in identities {
            if let Some(descriptor) = breeze::try_resolve_identity(&self.socks_dir, &identity)
                .with_context(|| {
                    format!(
                        "Memcached background rules cannot resolve Breeze resource {identity:?}"
                    )
                })?
            {
                resolved.push((identity, descriptor.port));
            }
        }
        if resolved.is_empty() {
            return Ok(());
        }

        let mut rules = self.memcached.lock().expect("background rules poisoned");
        for (identity, port) in resolved {
            let Some(resource_rules) = rules.pending_by_identity.remove(&identity) else {
                continue;
            };
            let rule_names = resource_rules
                .iter()
                .map(|rule| rule.name.as_str())
                .collect::<Vec<_>>()
                .join(",");
            rules
                .by_port
                .entry(port)
                .or_default()
                .extend(resource_rules);
            info!(
                %identity,
                port,
                rules = %rule_names,
                "Memcached background rules resolved a source-registered Breeze descriptor"
            );
        }
        Ok(())
    }

    fn pending_resource_summary(&self) -> String {
        let rules = self.memcached.lock().expect("background rules poisoned");
        let mut identities = rules
            .pending_by_identity
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        identities.sort();
        identities.join(",")
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

fn match_memcached_rule(
    rules: &MemcachedRules,
    target_port: u16,
    key: &[u8],
    exchange: &super::MemcachedExchangeEvent,
) -> Option<BackgroundDependencyMatch> {
    rules
        .by_port
        .get(&target_port)?
        .iter()
        .find(|rule| rule.matches(key))
        .map(|rule| BackgroundDependencyMatch {
            rule_name: rule.name.clone(),
            initial_load: Some(rule.initial_load.clone()),
            completed_response: exchange.outcome == DependencyExchangeOutcome::Response
                && !exchange.no_response
                && exchange.replay_safe,
        })
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
        memcached_rule_with(identity, 4095, 60_000)
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
    fn matches_exact_get_key_series_on_an_existing_descriptor() {
        let temp = tempfile::tempdir().unwrap();
        let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
        std::fs::write(temp.path().join(filename), "").unwrap();
        let identity = filename.replace(":9448", "");
        let matcher =
            BackgroundDependencyMatcher::from_rules_in(&[memcached_rule(identity)], temp.path())
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

    #[test]
    fn resolves_source_registered_descriptor_after_recorder_initialization() {
        let temp = tempfile::tempdir().unwrap();
        let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
        let identity = filename.replace(":9448", "");
        let matcher =
            BackgroundDependencyMatcher::from_rules_in(&[memcached_rule(identity)], temp.path())
                .unwrap();

        assert!(matcher.ensure_resources_resolved().is_err());
        assert!(
            matcher
                .matching_rule(&event(9449, "get", b"0.pl_video"))
                .is_none()
        );

        std::fs::write(temp.path().join(filename), "").unwrap();

        assert_eq!(
            matcher
                .matching_rule(&event(9448, "get", b"0.pl_video"))
                .map(|matched| matched.rule_name().to_string()),
            Some("planet-video-cache-warm".to_string())
        );
        assert!(matcher.pending_resource_summary().is_empty());
        matcher.ensure_resources_resolved().unwrap();
    }

    #[tokio::test]
    async fn initial_load_completion_uses_matching_exchange_count() {
        let temp = tempfile::tempdir().unwrap();
        let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
        std::fs::write(temp.path().join(filename), "").unwrap();
        let identity = filename.replace(":9448", "");
        let matcher = BackgroundDependencyMatcher::from_rules_in(
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

        matcher.wait_for_initial_loads().await;
    }

    #[tokio::test]
    async fn initial_load_timeout_is_non_fatal() {
        let temp = tempfile::tempdir().unwrap();
        let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
        std::fs::write(temp.path().join(filename), "").unwrap();
        let identity = filename.replace(":9448", "");
        let matcher = BackgroundDependencyMatcher::from_rules_in(
            &[memcached_rule_with(identity, 1, 5)],
            temp.path(),
        )
        .unwrap();
        let matched = matcher
            .matching_rule(&event(9448, "get", b"0.pl_video"))
            .unwrap();
        matcher.record_completed_match(&matched);

        matcher.wait_for_initial_loads().await;
        assert_eq!(matcher.pending_initial_loads().len(), 1);
    }
}
