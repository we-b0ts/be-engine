use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
use crate::config::process_owned_dependencies::{
    matches_exact_redis_key, matches_memcached_key_series,
};
use crate::dependency::DependencyExchangeOutcome;

use super::readiness::{PostReadyWaitOutcome, RedisCacheActivity};

const INITIAL_LOAD_PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(crate) struct BackgroundDependencyMatcher {
    rules: Vec<BackgroundDependencyRuleConfig>,
    api_rules: Vec<BackgroundDependencyRuleConfig>,
    socks_dir: PathBuf,
    memcached: Mutex<MemcachedRules>,
    redis_initial_load_rules: Vec<RedisInitialLoadRule>,
    initial_loads: InitialLoads,
    redis_cache_activity: RedisCacheActivity,
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
    key_start: u64,
    key_end: u64,
    key_separator: u8,
    key_suffix: Vec<u8>,
    initial_load: Arc<InitialLoad>,
}

#[derive(Debug, Clone)]
struct RedisInitialLoadRule {
    name: String,
    ports: Vec<u16>,
    command: String,
    keys: Vec<String>,
    initial_load: Arc<InitialLoad>,
}

#[derive(Debug)]
pub(crate) struct BackgroundDependencyMatch {
    rule_name: String,
    initial_load: Option<Arc<InitialLoad>>,
    completion_key: Option<Vec<u8>>,
    completed_response: bool,
}

#[derive(Debug)]
struct InitialLoad {
    name: String,
    expected: u64,
    timeout: Duration,
    completed: AtomicU64,
    seen_keys: Option<Mutex<HashSet<Vec<u8>>>>,
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
    pub(crate) fn matching_memcached_requests(&self, port: u16, key: &[u8]) -> Vec<String> {
        let select = || {
            let rules = self.memcached.lock().expect("background rules poisoned");
            rules
                .by_port
                .get(&port)
                .into_iter()
                .flatten()
                .filter(|rule| rule.matches(key))
                .map(|rule| rule.name.clone())
                .collect::<Vec<_>>()
        };
        // Other resources may resolve onto this port too. Refresh before taking
        // the full candidate set rather than accepting the first cached match.
        let _ = self.refresh_pending_resources();
        select()
    }

    pub(crate) fn matching_capture_rules(&self, event: &RecorderEvent) -> Vec<String> {
        let mut rules = self
            .rules
            .iter()
            .filter(|rule| rule.matches(event))
            .map(|rule| rule.name().to_owned())
            .collect::<BTreeSet<_>>();
        match event {
            RecorderEvent::MemcachedExchange(exchange)
                if exchange.command.eq_ignore_ascii_case("get") =>
            {
                if let Some(key) = exchange.key.as_ref().and_then(decode_capture) {
                    rules.extend(self.matching_memcached_requests(exchange.target_port, &key));
                }
            }
            RecorderEvent::RedisExchange(exchange) if !exchange.session_setup => {
                if let Some(key) = exchange.args.first().and_then(decode_capture) {
                    rules.extend(
                        self.redis_initial_load_rules
                            .iter()
                            .filter(|rule| {
                                rule.ports.contains(&exchange.target_port)
                                    && exchange.command.eq_ignore_ascii_case(&rule.command)
                                    && matches_exact_redis_key(&key, &rule.keys)
                            })
                            .map(|rule| rule.name.clone()),
                    );
                }
            }
            _ => (),
        }
        rules.into_iter().collect()
    }

    pub(crate) fn from_rules(rules: &[BackgroundDependencyRuleConfig]) -> Result<Self> {
        Self::from_rules_in(rules, Path::new(breeze::SOCKS_DIR))
    }

    fn from_rules_in(rules: &[BackgroundDependencyRuleConfig], socks_dir: &Path) -> Result<Self> {
        let mut rules_without_specialized_matching = Vec::new();
        let mut api_rules = Vec::new();
        let mut memcached = MemcachedRules::default();
        let mut redis_initial_load_rules = Vec::new();
        let mut initial_loads = InitialLoads::default();
        for rule in rules {
            match rule {
                rule if rule.trigger_source().is_some() => {
                    api_rules.push(rule.clone());
                }
                BackgroundDependencyRuleConfig::Mysql { .. }
                | BackgroundDependencyRuleConfig::Http { .. }
                | BackgroundDependencyRuleConfig::RedisPubsub { .. }
                | BackgroundDependencyRuleConfig::Motan { .. } => {
                    rules_without_specialized_matching.push(rule.clone());
                }
                BackgroundDependencyRuleConfig::Redis {
                    name,
                    ports,
                    command,
                    keys,
                    initial_load_timeout_ms,
                    ..
                } if initial_load_timeout_ms.is_some() => {
                    let timeout_ms = initial_load_timeout_ms
                        .context("validated Redis initial-load rule has no timeout")?;
                    let initial_load = Arc::new(InitialLoad {
                        name: name.clone(),
                        expected: keys.len() as u64,
                        timeout: Duration::from_millis(timeout_ms),
                        completed: AtomicU64::new(0),
                        seen_keys: Some(Mutex::new(HashSet::new())),
                    });
                    initial_loads.rules.push(initial_load.clone());
                    redis_initial_load_rules.push(RedisInitialLoadRule {
                        name: name.clone(),
                        ports: ports.clone(),
                        command: command.clone(),
                        keys: keys.clone(),
                        initial_load,
                    });
                }
                BackgroundDependencyRuleConfig::Redis { .. } => {
                    rules_without_specialized_matching.push(rule.clone());
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
                    let expected = key_end
                        .checked_sub(*key_start)
                        .and_then(|value| value.checked_add(1))
                        .context("validated Memcached key range overflowed")?;
                    let initial_load = Arc::new(InitialLoad {
                        name: name.clone(),
                        expected,
                        timeout: Duration::from_millis(*initial_load_timeout_ms),
                        completed: AtomicU64::new(0),
                        seen_keys: None,
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
            rules: rules_without_specialized_matching,
            api_rules,
            socks_dir: socks_dir.to_path_buf(),
            memcached: Mutex::new(memcached),
            redis_initial_load_rules,
            initial_loads,
            redis_cache_activity: RedisCacheActivity::default(),
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
        if let RecorderEvent::RedisExchange(exchange) = event
            && !exchange.session_setup
            && exchange.replay_safe
        {
            let key = exchange.args.first().and_then(decode_capture)?;
            if let Some(rule) = self.redis_initial_load_rules.iter().find(|rule| {
                rule.ports.contains(&exchange.target_port)
                    && exchange.command.eq_ignore_ascii_case(&rule.command)
                    && matches_exact_redis_key(&key, &rule.keys)
            }) {
                return Some(BackgroundDependencyMatch {
                    rule_name: rule.name.clone(),
                    initial_load: Some(rule.initial_load.clone()),
                    completion_key: Some(key),
                    completed_response: exchange.outcome == DependencyExchangeOutcome::Response,
                });
            }
        }
        self.rules
            .iter()
            .find(|rule| rule.matches(event))
            .map(|rule| BackgroundDependencyMatch {
                rule_name: rule.name().to_string(),
                initial_load: None,
                completion_key: None,
                completed_response: false,
            })
    }

    pub(crate) fn matching_api_candidate(&self, event: &RecorderEvent) -> Option<&str> {
        if self.api_rules.is_empty() {
            return None;
        }
        if let RecorderEvent::MysqlExchange(exchange) = event {
            if !self.api_rules.iter().any(|r| {
                matches!(r, BackgroundDependencyRuleConfig::Mysql {selector, ..}
                if exchange.target_port == Some(selector.target_port))
            }) {
                return None;
            }
            let mut value = serde_json::to_value(exchange).ok()?;
            value["event_type"] = "mysql_exchange".into();
            return self
                .api_rules
                .iter()
                .find(|rule| {
                    crate::config::api_trigger::mysql::identity(rule, &value).is_some()
                        && crate::config::api_trigger::mysql::complete(&value)
                })
                .map(|rule| rule.name());
        }
        let RecorderEvent::RedisExchange(exchange) = event else {
            return None;
        };
        if exchange.session_setup || !exchange.replay_safe
            || !self.api_rules.iter().any(|rule| matches!(rule,
                BackgroundDependencyRuleConfig::Redis { ports, command, .. }
                if ports.contains(&exchange.target_port) && (command.eq_ignore_ascii_case(&exchange.command) || (command == "EVALSHA" && exchange.command == "SCRIPT")))) {
            return None;
        }
        let args = exchange
            .args
            .iter()
            .map(decode_capture)
            .collect::<Option<Vec<_>>>()?;
        self.api_rules
            .iter()
            .find(|rule| {
                if let BackgroundDependencyRuleConfig::Redis {
                    ports,
                    script: Some(script),
                    ..
                } = rule
                    && ports.contains(&exchange.target_port)
                    && exchange.command == "SCRIPT"
                    && script.exists(&args)
                {
                    return true;
                }
                crate::config::api_trigger::redis_identity(
                    rule,
                    exchange.target_port,
                    &exchange.command,
                    &args,
                )
                .is_some()
            })
            .map(|rule| rule.name())
    }

    pub(crate) fn matching_redis_snapshot_rule(
        &self,
        target_port: u16,
        command: &str,
        args: &[Vec<u8>],
    ) -> Option<&str> {
        self.redis_initial_load_rules
            .iter()
            .find(|rule| {
                rule.ports.contains(&target_port)
                    && rule.command.eq_ignore_ascii_case(command)
                    && args
                        .first()
                        .is_some_and(|key| matches_exact_redis_key(key, &rule.keys))
            })
            .map(|rule| rule.name.as_str())
            .or_else(|| {
                self.rules.iter().find_map(|rule| {
                    (rule.uses_redis_snapshot()
                        && crate::config::process_owned_dependencies::redis_rule_matches(
                            rule,
                            target_port,
                            command,
                            args,
                        ))
                    .then(|| rule.name())
                })
            })
    }

    pub(crate) fn has_redis_snapshot_port(&self, port: u16) -> bool {
        self.redis_initial_load_rules
            .iter()
            .any(|rule| rule.ports.contains(&port))
            || self.rules.iter().any(|rule| {
                matches!(
                    rule,
                    BackgroundDependencyRuleConfig::Redis { ports, trigger_source: None, .. }
                        if rule.uses_redis_snapshot() && ports.contains(&port)
                )
            })
    }

    pub(crate) fn record_redis_cache_request(&self) {
        self.redis_cache_activity.record_request();
    }

    pub(crate) async fn wait_for_redis_cache_quiet_period(
        &self,
        ready_at: Instant,
        quiet_period: Duration,
        maximum_wait: Duration,
    ) -> PostReadyWaitOutcome {
        self.redis_cache_activity
            .wait_for_quiet_period(ready_at, quiet_period, maximum_wait)
            .await
    }

    pub(crate) fn record_completed_match(&self, matched: &BackgroundDependencyMatch) {
        if !matched.completed_response {
            return;
        }
        let Some(initial_load) = &matched.initial_load else {
            return;
        };
        if let Some(key) = &matched.completion_key {
            let Some(seen_keys) = &initial_load.seen_keys else {
                return;
            };
            if !seen_keys
                .lock()
                .expect("background initial-load keys poisoned")
                .insert(key.clone())
            {
                return;
            }
        }
        let previous =
            initial_load
                .completed
                .try_update(Ordering::AcqRel, Ordering::Acquire, |completed| {
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
                    "background initial load completed"
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

    pub(crate) fn resolved_memcached_rule_ports(&self) -> BTreeMap<String, BTreeSet<u16>> {
        let _ = self.refresh_pending_resources();
        let rules = self.memcached.lock().expect("background rules poisoned");
        let mut resolved = BTreeMap::<String, BTreeSet<u16>>::new();
        for (port, resource_rules) in &rules.by_port {
            for rule in resource_rules {
                resolved.entry(rule.name.clone()).or_default().insert(*port);
            }
        }
        resolved
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
            "background initial load observation started"
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
                    "background initial load observation window elapsed; continuing recording"
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
                        "background initial load observation is still waiting"
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
            completion_key: None,
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
#[path = "background/tests.rs"]
mod tests;
