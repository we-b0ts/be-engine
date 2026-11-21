//! Validated execution budgets and explicit business-completion contracts.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct InteractionPolicy {
    pub business_idle_ms: u64,
    pub max_duration_ms: u64,
    pub cleanup_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub input_gap_ms: u64,
    /// Preserve client timing for clock-sensitive or deliberately delayed interactions.
    pub preserve_input_timing: bool,
    pub max_message_bytes: usize,
    pub max_messages: usize,
    pub max_total_bytes: usize,
    pub completion: Vec<EventCompletion>,
    /// A stream terminal marker is an explicit contract, never a protocol guess.
    pub stream_terminal: Option<StreamTerminal>,
}

impl Default for InteractionPolicy {
    fn default() -> Self {
        Self {
            business_idle_ms: 10_000,
            max_duration_ms: 900_000,
            cleanup_timeout_ms: 60_000,
            request_timeout_ms: 900_000,
            input_gap_ms: 100,
            preserve_input_timing: false,
            max_message_bytes: 8 * 1024 * 1024,
            max_messages: 100_000,
            max_total_bytes: 64 * 1024 * 1024,
            completion: Vec::new(),
            stream_terminal: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventCompletion {
    #[serde(default = "root_namespace")]
    pub namespace: String,
    pub event: String,
    pub completion: CompletionRule,
}

fn root_namespace() -> String {
    "/".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompletionRule {
    Ack,
    TerminalEvent {
        event: String,
        #[serde(default)]
        correlation: Option<CorrelationRule>,
        #[serde(default)]
        require_ack: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorrelationRule {
    /// JSON pointers address the argument array, e.g. `/0/task_id`.
    pub input_pointer: String,
    pub output_pointer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StreamTerminal {
    SseEvent {
        event: String,
    },
    Text {
        value: String,
    },
    Json {
        pointer: String,
        value: serde_json::Value,
    },
}

impl InteractionPolicy {
    pub fn validate(&self) -> Result<()> {
        for milliseconds in [
            self.business_idle_ms,
            self.max_duration_ms,
            self.cleanup_timeout_ms,
            self.request_timeout_ms,
            self.input_gap_ms,
        ] {
            ensure!(
                std::time::Instant::now()
                    .checked_add(std::time::Duration::from_millis(milliseconds))
                    .is_some(),
                "interaction time budget exceeds the monotonic clock range"
            );
        }
        ensure!(
            self.business_idle_ms > 0,
            "interaction business_idle_ms must be positive"
        );
        ensure!(
            self.max_duration_ms > 0,
            "interaction max_duration_ms must be positive"
        );
        ensure!(
            self.cleanup_timeout_ms > 0,
            "interaction cleanup_timeout_ms must be positive"
        );
        ensure!(
            self.request_timeout_ms > 0,
            "interaction request_timeout_ms must be positive"
        );
        ensure!(
            self.input_gap_ms < self.business_idle_ms,
            "interaction input_gap_ms must be less than business idle"
        );
        ensure!(
            self.max_message_bytes > 0
                && self.max_messages > 0
                && self.max_total_bytes >= self.max_message_bytes,
            "invalid interaction message budgets"
        );
        let mut identities = std::collections::BTreeSet::new();
        for rule in &self.completion {
            ensure!(
                rule.namespace.starts_with('/') && !rule.namespace.contains(','),
                "invalid Socket.IO completion namespace"
            );
            ensure!(
                !rule.event.is_empty(),
                "Socket.IO completion event must not be empty"
            );
            ensure!(
                identities.insert((&rule.namespace, &rule.event)),
                "duplicate Socket.IO completion rule"
            );
            if let CompletionRule::TerminalEvent {
                event, correlation, ..
            } = &rule.completion
            {
                ensure!(
                    !event.is_empty(),
                    "Socket.IO terminal event must not be empty"
                );
                if let Some(correlation) = correlation {
                    validate_pointer(&correlation.input_pointer)?;
                    validate_pointer(&correlation.output_pointer)?;
                }
            }
        }
        if let Some(StreamTerminal::Json { pointer, .. }) = &self.stream_terminal {
            validate_pointer(pointer)?;
        }
        Ok(())
    }

    pub fn completion_for(&self, namespace: &str, event: &str) -> Option<&CompletionRule> {
        self.completion
            .iter()
            .find(|rule| rule.namespace == namespace && rule.event == event)
            .map(|rule| &rule.completion)
    }
}

fn validate_pointer(pointer: &str) -> Result<()> {
    ensure!(
        pointer.is_empty() || pointer.starts_with('/'),
        "correlation selector must be a JSON pointer"
    );
    let bytes = pointer.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'~' {
            ensure!(
                matches!(bytes.get(index + 1), Some(b'0' | b'1')),
                "invalid JSON pointer escape"
            );
        }
    }
    Ok(())
}
