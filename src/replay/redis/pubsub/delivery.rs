//! Case-bound Global input stays in the started-I/O barrier through wire delivery.
use super::*;

impl PubSubState {
    fn slot_target(&self, slot: PushId) -> TargetKey {
        let record = match slot {
            PushId::Inline(index) => &self.pushes[index].record,
            PushId::Indexed { lane, .. } => &self.indexed.lanes[lane].record,
        };
        TargetKey {
            host: normalize_host(&record.target_host),
            port: record.target_port,
        }
    }
    pub(in crate::replay) fn has_case_delivery(&self) -> bool {
        !self.case_deliveries.is_empty()
    }
    pub(super) fn reserve_case_push(&mut self, slot: PushId, case: &str, client: Uuid) {
        self.reserve_push(slot);
        self.case_deliveries.insert(slot, (case.into(), client));
    }
    pub(in crate::replay) fn case_delivery_diagnostic(&self) -> serde_json::Value {
        serde_json::json!({"count":self.case_deliveries.len(),"references":self.case_deliveries.iter().take(4)
            .map(|(slot,(case,_))|serde_json::json!({"slot":format!("{slot:?}"),"case_id":case})).collect::<Vec<_>>(),
            "omitted":self.case_deliveries.len().saturating_sub(4)})
    }
    fn pending_client(&self, client: Uuid) -> Vec<(PushId, String)> {
        self.case_deliveries
            .iter()
            .filter(|(_, (_, owner))| *owner == client)
            .map(|(slot, (case, _))| (*slot, case.clone()))
            .collect()
    }
}
impl super::super::RedisReplayState {
    pub(in crate::replay::redis) fn fail_pubsub_input(
        &mut self,
        slot: PushId,
        case: Option<&str>,
        reason: &str,
    ) {
        let target = self.pubsub.slot_target(slot);
        self.pubsub.fail(slot);
        if let Some(case) = case {
            self.events.dirty_case_ids.insert(case.into());
            self.events.unsafe_events.push(CommandRequestReport {
                target_observation_id: None,
                case_id: Some(case.into()),
                target,
                command: "PUBSUB_PUSH".into(),
                target_event_index: None,
                request_fingerprint: None,
                reason: reason.into(),
                diagnostic: None,
            });
        }
        self.delivery_changed.notify_waiters();
    }
    pub(in crate::replay::redis) fn finish_pubsub_client(&mut self, client: Uuid) {
        for (slot, case) in self.pubsub.pending_client(client) {
            self.fail_pubsub_input(
                slot,
                Some(&case),
                "Case input subscription closed before wire delivery",
            );
        }
        self.delivery_changed.notify_waiters();
    }
}
