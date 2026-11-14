//! Case-bound Global input stays in the started-I/O barrier through wire delivery.
use super::*;

/// Value preparation, the actual write and its finite receipt share one owner.
pub(in crate::replay::redis) async fn deliver_input(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    state: &Arc<Mutex<ReplayState>>,
    client: Uuid,
    mut delivery: Delivery,
) -> Result<()> {
    let _callback_guard = delivery
        .matched
        .as_ref()
        .and_then(|matched| match &matched.claim {
            Claim::Finite(ticket) => Some(ticket.guard()),
            Claim::Native(_) => None,
        });
    let mut replay = state.lock().await;
    if !delivery.case_is_current(&replay)
        || replay.finalized_at.is_some()
        || !replay
            .protocols
            .redis
            .pubsub
            .is_subscribed(client, delivery.push)
    {
        reject(
            &mut replay,
            &delivery,
            "Pub/Sub input Case or subscription already ended",
        );
        return Ok(());
    }
    let push = delivery.push;
    let value_bytes = match super::value_delivery::render(&replay, &mut delivery) {
        Ok(bytes) => bytes,
        Err(error) => {
            reject(
                &mut replay,
                &delivery,
                "Pub/Sub input value contract failed",
            );
            return Err(error.context("Pub/Sub input value contract failed"));
        }
    };
    let bytes = match super::subject_delivery::render(
        &replay.protocols.redis.pubsub,
        client,
        push,
        &value_bytes,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            reject(
                &mut replay,
                &delivery,
                "Pub/Sub input subject translation failed",
            );
            return Err(error.context("Pub/Sub input subject translation failed"));
        }
    };
    let timing_scope = super::super::input_timing::scope(&replay);
    drop(replay);
    let sent = tokio::time::timeout(std::time::Duration::from_secs(5), writer.write_all(&bytes))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Pub/Sub push delivery timed out",
            )
        })
        .and_then(|result| result);
    let written_at = tokio::time::Instant::now();
    let mut replay = state.lock().await;
    match sent {
        Ok(()) if !delivery.case_is_current(&replay) => {
            reject(
                &mut replay,
                &delivery,
                "Pub/Sub input Case changed during delivery",
            );
        }
        Ok(()) => {
            replay.protocols.redis.pubsub.complete(delivery.push);
            if let (Some(case), Some(epoch)) = (&delivery.case_id, delivery.request_epoch) {
                replay.protocols.redis.pubsub.native_clock.fast_written(
                    case,
                    epoch,
                    delivery.push,
                    written_at,
                );
            }
            super::super::input_timing::delivered(
                &mut replay,
                timing_scope.as_ref(),
                crate::replay::control::input_timing::DeliveryReference::NativePush(delivery.push),
            );
            replay.protocols.redis.lifecycle.notify_waiters();
            if let Some(matched) = &delivery.matched {
                replay.protocols.redis.complete_exchange(matched);
            }
        }
        Err(error) => {
            reject(&mut replay, &delivery, "Pub/Sub input TCP delivery failed");
            return Err(error.into());
        }
    }
    Ok(())
}

fn reject(replay: &mut ReplayState, delivery: &Delivery, reason: &str) {
    replay
        .protocols
        .redis
        .fail_pubsub_input(delivery.push, delivery.case_id.as_deref(), reason);
    if let Some(matched) = &delivery.matched {
        replay.protocols.redis.fail_exchange(matched, reason.into());
    }
}

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
        self.lifecycle.notify_waiters();
    }
    pub(in crate::replay::redis) fn finish_pubsub_client(&mut self, client: Uuid) {
        for (slot, case) in self.pubsub.pending_client(client) {
            self.fail_pubsub_input(
                slot,
                Some(&case),
                "Case input subscription closed before wire delivery",
            );
        }
        self.lifecycle.notify_waiters();
    }
}
