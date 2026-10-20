//! A single monotonic lifecycle shared by stream and Socket.IO adapters.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};

use super::{
    model::{EndObservation, EndReason},
    policy::InteractionPolicy,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleDecision {
    Continue,
    Close(EndReason),
    Fail(EndReason),
}

#[derive(Debug)]
pub struct InteractionLifecycle {
    policy: InteractionPolicy,
    started_ms: u64,
    last_activity_ms: u64,
    pending: BTreeMap<u64, u64>,
    messages: usize,
    bytes: usize,
}

impl InteractionLifecycle {
    pub fn new(policy: InteractionPolicy, started_ms: u64) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            policy,
            started_ms,
            last_activity_ms: started_ms,
            pending: BTreeMap::new(),
            messages: 0,
            bytes: 0,
        })
    }

    pub fn begin(&mut self, id: u64, now_ms: u64) -> Result<()> {
        ensure!(
            !self.pending.contains_key(&id),
            "duplicate interaction request identity"
        );
        self.pending.insert(id, now_ms);
        self.activity(now_ms);
        Ok(())
    }

    pub fn complete(&mut self, id: u64, now_ms: u64) -> Result<()> {
        ensure!(
            self.pending.remove(&id).is_some(),
            "unknown interaction completion identity"
        );
        self.activity(now_ms);
        Ok(())
    }

    /// Call only for business traffic, including explicitly configured application heartbeats.
    pub fn activity(&mut self, now_ms: u64) {
        self.last_activity_ms = self.last_activity_ms.max(now_ms);
    }

    pub fn pending(&self) -> Vec<u64> {
        self.pending.keys().copied().collect()
    }

    pub fn is_pending(&self, id: u64) -> bool {
        self.pending.contains_key(&id)
    }

    pub fn record_message(&mut self, bytes: usize) -> Result<()> {
        ensure!(
            bytes <= self.policy.max_message_bytes,
            "interaction message budget exceeded"
        );
        let count = self
            .messages
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("interaction message count overflow"))?;
        let total = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("interaction byte count overflow"))?;
        ensure!(
            count <= self.policy.max_messages && total <= self.policy.max_total_bytes,
            "interaction capture budget exceeded"
        );
        self.messages = count;
        self.bytes = total;
        Ok(())
    }

    pub fn decision(&self, now_ms: u64) -> LifecycleDecision {
        if now_ms.saturating_sub(self.started_ms) >= self.policy.max_duration_ms {
            return LifecycleDecision::Fail(EndReason::MaxDuration);
        }
        if self
            .pending
            .values()
            .any(|started| now_ms.saturating_sub(*started) >= self.policy.request_timeout_ms)
        {
            return LifecycleDecision::Fail(EndReason::RequestTimeout);
        }
        if self.pending.is_empty()
            && now_ms.saturating_sub(self.last_activity_ms) >= self.policy.business_idle_ms
        {
            return LifecycleDecision::Close(EndReason::BusinessIdle);
        }
        LifecycleDecision::Continue
    }

    /// A client cancellation can be completely observed while business is pending.
    /// Pending work remains evidence; cancellation must not fabricate completion.
    pub fn end_observation(
        &self,
        reason: EndReason,
        now_ms: u64,
        transport_clean: bool,
    ) -> EndObservation {
        let success_reason = matches!(
            reason,
            EndReason::BusinessIdle | EndReason::ServerEof | EndReason::ClientClose
        );
        EndObservation {
            reason,
            offset_ms: now_ms.saturating_sub(self.started_ms),
            pending: self.pending(),
            clean: transport_clean
                && success_reason
                && (self.pending.is_empty() || reason == EndReason::ClientClose),
            partial_message: None,
            close: None,
        }
    }

    pub fn next_deadline_ms(&self) -> u64 {
        let hard = self.started_ms.saturating_add(self.policy.max_duration_ms);
        if self.pending.is_empty() {
            hard.min(
                self.last_activity_ms
                    .saturating_add(self.policy.business_idle_ms),
            )
        } else {
            self.pending
                .values()
                .map(|started| started.saturating_add(self.policy.request_timeout_ms))
                .min()
                .unwrap_or(hard)
                .min(hard)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_pending_requests_suppress_idle_and_timeout_independently() {
        let mut lifecycle = InteractionLifecycle::new(
            InteractionPolicy {
                request_timeout_ms: 120_000,
                max_duration_ms: 600_000,
                ..Default::default()
            },
            0,
        )
        .unwrap();
        lifecycle.begin(1, 0).unwrap();
        lifecycle.begin(2, 5_000).unwrap();
        lifecycle.complete(1, 8_000).unwrap();
        assert_eq!(lifecycle.decision(50_000), LifecycleDecision::Continue);
        assert_eq!(
            lifecycle.decision(125_000),
            LifecycleDecision::Fail(EndReason::RequestTimeout)
        );
        lifecycle.complete(2, 125_001).unwrap();
        assert_eq!(lifecycle.decision(135_000), LifecycleDecision::Continue);
        assert_eq!(
            lifecycle.decision(135_001),
            LifecycleDecision::Close(EndReason::BusinessIdle)
        );
    }

    #[test]
    fn eof_does_not_certify_pending_business_and_hard_duration_is_not_success() {
        let mut lifecycle = InteractionLifecycle::new(
            InteractionPolicy {
                max_duration_ms: 600_000,
                ..Default::default()
            },
            0,
        )
        .unwrap();
        lifecycle.begin(4, 0).unwrap();
        assert!(
            !lifecycle
                .end_observation(EndReason::ServerEof, 10, true)
                .clean
        );
        assert_eq!(
            lifecycle.decision(600_000),
            LifecycleDecision::Fail(EndReason::MaxDuration)
        );
    }

    #[test]
    fn completion_keeps_connection_open_and_new_business_restarts_idle() {
        let mut lifecycle = InteractionLifecycle::new(InteractionPolicy::default(), 0).unwrap();
        lifecycle.begin(1, 0).unwrap();
        lifecycle.complete(1, 100).unwrap();
        assert_eq!(lifecycle.decision(100), LifecycleDecision::Continue);
        assert_eq!(lifecycle.decision(10_099), LifecycleDecision::Continue);
        assert_eq!(
            lifecycle.decision(10_100),
            LifecycleDecision::Close(EndReason::BusinessIdle)
        );
        lifecycle.activity(5_000);
        assert_eq!(lifecycle.decision(10_100), LifecycleDecision::Continue);
        assert_eq!(lifecycle.next_deadline_ms(), 15_000);
        assert_eq!(
            lifecycle.decision(15_000),
            LifecycleDecision::Close(EndReason::BusinessIdle)
        );
    }
}
