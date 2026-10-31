//! Independent Target observation and arrival reservation precede native selection.
use super::*;

impl ReplayState {
    pub(in crate::replay::mysql) fn observe_mysql_request(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
    ) -> crate::replay::admission::RequestAdmission {
        #[cfg(not(test))]
        let request_observed_at = Utc::now();
        #[cfg(test)]
        let request_observed_at = self.mysql.observed_at_for_test.unwrap_or_else(Utc::now);
        let event_index = self.mysql.events.request_order.reserve(case);
        let mut observation_id = Some(uuid::Uuid::new_v4());
        let request = contracts::ObservedRequest {
            observation_id,
            command,
            sql,
            params,
            started_at: request_observed_at,
        };
        let retention = if let (Some(policy), Some(case)) = (&self.replay_policy, case) {
            contracts::record_target(&policy.request_contracts, case, identity, request)
        } else {
            contracts::record_unanchored_target(&self.target_observations, case, identity, request)
        };
        let observation_retained = self.target_observations.retained(&retention);
        if matches!(
            &retention,
            Ok(crate::policy_evidence::ObservationRetention::Unavailable)
        ) {
            observation_id = None;
        }
        if retention.is_err() {
            self.mysql.events.metadata_warnings.push("independent SQL Target observation unavailable; inspect target_observation_coverage_error".into());
        }
        self.mysql.request_observation_id =
            observation_id.filter(|_| observation_retained).map(|id| {
                crate::policy_evidence::target_observation_id(
                    &id.to_string(),
                    crate::policy::Surface::DependencyRequest,
                    crate::policy_evidence::TargetRole::IndependentTargetObservation,
                )
            });
        crate::replay::admission::RequestAdmission::capture(
            self,
            Some(event_index),
            Some(request_observed_at),
            observation_id,
            observation_retained,
        )
    }
}
