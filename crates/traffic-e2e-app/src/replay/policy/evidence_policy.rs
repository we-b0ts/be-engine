//! Shared policy identity checks for rule evidence and diagnostic projections.
use anyhow::{Result, ensure};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReplayEvidencePolicyFreshness {
    pub(crate) status: &'static str,
    pub(crate) evidence_policy_fingerprint: Option<String>,
    pub(crate) current_policy_fingerprint: String,
    pub(crate) requires_fresh_replay: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unavailable_reason: Option<String>,
}

impl ReplayEvidencePolicyFreshness {
    pub(crate) fn new(evidence: Option<&str>, current: &str) -> Self {
        let status = match evidence {
            Some(value) if value == current => "current",
            Some(_) => "stale",
            None => "unavailable",
        };
        Self {
            status,
            evidence_policy_fingerprint: evidence.map(str::to_owned),
            current_policy_fingerprint: current.into(),
            requires_fresh_replay: status != "current",
            unavailable_reason: None,
        }
    }

    pub(crate) fn unavailable(current: &str, reason: String) -> Self {
        Self {
            unavailable_reason: Some(reason),
            ..Self::new(None, current)
        }
    }

    pub(crate) fn ensure_current(&self, description: &str) -> Result<()> {
        ensure!(
            !self.requires_fresh_replay,
            "{description} uses a different policy: evidence={}, current={}. Run fresh Replay for this API using the existing recordings and current the configured project.policy, then query new evidence and plan again. Changing evidence IDs or rule selectors does not refresh Replay evidence.",
            self.evidence_policy_fingerprint
                .as_deref()
                .unwrap_or("unavailable"),
            self.current_policy_fingerprint,
        );
        Ok(())
    }
}
