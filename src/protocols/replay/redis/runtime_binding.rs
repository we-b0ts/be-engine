//! Bind shared evidence and rule services to the prepared Redis adapter state.
use super::*;
use crate::policy::runtime::ReplayPolicyRuntime;
use crate::replay::TargetObservations;
use chrono::{DateTime, Utc};

impl RedisReplayState {
    pub(crate) fn register_policy_sources(&self, policy: &mut ReplayPolicyRuntime) -> Result<()> {
        for (case, directory) in &self.shared_source_directories {
            policy
                .request_contracts
                .register_source_origin(case, directory)?;
        }
        Ok(())
    }

    pub(crate) fn bind_runtime(
        &mut self,
        observations: TargetObservations,
        policy: Option<&ReplayPolicyRuntime>,
    ) {
        self.target_observations = Some(observations);
        if let Some(policy) = policy {
            self.dynamic_values = policy.dynamic_values.clone();
            self.request_contracts = policy.request_contracts.clone();
        }
    }
}

impl crate::replay::protocol_runtime::events::NativeEventProjection for RedisReplayState {
    fn request_begin(&mut self, case: &str, epoch: DateTime<Utc>) -> Result<()> {
        self.pubsub.native_clock.request_begin(case, epoch)?;
        self.pubsub.namespace_sessions.request_begin(case, epoch)
    }
    fn needs_native_events(&self, case: &str) -> bool {
        RedisReplayState::needs_native_events(self, case)
    }
    fn request_epoch(&self, case: &str) -> Option<DateTime<Utc>> {
        self.native_request_epoch(case)
    }
    fn begin(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
    ) -> crate::replay::protocol_runtime::events::EventCapabilities {
        crate::replay::protocol_runtime::events::EventCapabilities {
            enabled: self.native_events_begin(case, epoch),
            events: self.needs_ingress_events(case),
            input_acks: self.pubsub.native_clock.needs_input_acks(case),
        }
    }
    fn input_acknowledged(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        sequence: u64,
    ) -> Result<()> {
        self.pubsub
            .native_clock
            .input_acknowledged(case, epoch, sequence)
    }
    fn connected(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        namespace: &str,
        sid: Option<&str>,
    ) -> Result<()> {
        self.pubsub.native_clock.connected(case, epoch, namespace)?;
        self.pubsub
            .namespace_sessions
            .connected(case, epoch, namespace, sid)
    }
    fn observe(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        event: &crate::interaction::replay::NativeEvent,
    ) -> Result<()> {
        self.observe_native_event(case, epoch, event)
    }
}
