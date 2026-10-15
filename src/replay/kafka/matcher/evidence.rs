//! Global produce values and delivery records remain in immutable evidence.
use super::*;
use crate::dependency_index::RecordRef;

impl KafkaReplayState {
    pub(in crate::replay) fn register_global_produce(
        &mut self,
        record: RecordedKafkaProduce,
        reference: RecordRef,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        self.register_produce(record, ReplaySource::Global, None, targets)?;
        let exchange = self.produces.last_mut().expect("registered Kafka produce");
        exchange.evidence = Some(reference);
        exchange.record.key = None;
        exchange.record.value = None;
        exchange.record.headers = Vec::new();
        Ok(())
    }

    pub(in crate::replay) fn register_global_delivery(
        &mut self,
        record: RecordedKafkaDelivery,
        reference: RecordRef,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        self.register_delivery(record, ReplaySource::Global, None, targets)?;
        let exchange = self
            .deliveries
            .last_mut()
            .expect("registered Kafka delivery");
        exchange.evidence = Some(reference);
        exchange.record.key = None;
        exchange.record.value = None;
        exchange.record.headers = Vec::new();
        Ok(())
    }
}

impl ReplayKafkaProduce {
    pub(super) fn matches(&self, actual: &KafkaRecord) -> bool {
        if self.record.topic != actual.topic {
            return false;
        }
        let Some(reference) = &self.evidence else {
            return semantic_record_matches(&self.record, actual);
        };
        reference
            .load::<RecordedKafkaProduce>()
            .and_then(|record| {
                decode_record(record.topic, record.key, record.headers, record.value, 0)
            })
            .is_ok_and(|record| semantic_record_matches(&record, actual))
    }
}

impl ReplayKafkaDelivery {
    pub(super) fn materialize(&self) -> Result<KafkaRecord> {
        let Some(reference) = &self.evidence else {
            return Ok(self.record.clone());
        };
        let record: RecordedKafkaDelivery = reference.load()?;
        decode_record(
            record.topic,
            record.key,
            record.headers,
            record.value,
            record.message_timestamp_ms,
        )
    }
}

impl KafkaReplayState {
    pub(in crate::replay) fn visit_global_unused(
        &self,
        visitor: &mut dyn FnMut(serde_json::Value) -> Result<()>,
    ) -> Result<()> {
        for item in self.unused_iter(ReplaySource::Global) {
            visitor(serde_json::to_value(item)?)?;
        }
        Ok(())
    }
    pub(in crate::replay) fn global_unused_count(&self) -> usize {
        self.unused_iter(ReplaySource::Global).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn global_kafka_payloads_keep_exact_produce_matching_and_finite_fetch_delivery() {
        let capture = |data| json!({"encoding":"utf8","data":data,"truncated":false});
        let produce = json!({"event_type":"kafka_produce","connection_id":Uuid::nil(),"request_sequence":1,
            "target_host":"kafka.test","target_port":9092,"topic":"items","key":capture("key"),"value":capture("value"),
            "headers":[{"name":"id","value":capture("header")}],"result":"accepted","outcome":"response","duration_ms":0,"replay_safe":true});
        let fetch = json!({"event_type":"kafka_fetch","connection_id":Uuid::nil(),"sequence":2,
            "target_host":"kafka.test","target_port":9092,"topics":["items"],"outcome":"response","duration_ms":0,"replay_safe":true});
        let delivery = json!({"event_type":"kafka_delivery","connection_id":Uuid::nil(),"fetch_sequence":2,
            "target_host":"kafka.test","target_port":9092,"topic":"items","key":capture("key"),"value":capture("delivered"),
            "headers":[{"name":"id","value":capture("header")}],"message_timestamp_ms":123,"replay_safe":true});
        let (_dir, mut entries) =
            crate::replay::global_test_support::indexed(&[produce.clone(), fetch, delivery]);
        let (record, reference) = entries.remove(0);
        let mut state = KafkaReplayState::default();
        let mut targets = BTreeMap::new();
        state
            .register_global_produce(
                serde_json::from_value(record).unwrap(),
                reference,
                &mut targets,
            )
            .unwrap();
        let (record, _) = entries.remove(0);
        state
            .register_fetch(
                serde_json::from_value(record).unwrap(),
                ReplaySource::Global,
                None,
                &mut targets,
            )
            .unwrap();
        let (record, reference) = entries.remove(0);
        state
            .register_global_delivery(
                serde_json::from_value(record).unwrap(),
                reference,
                &mut targets,
            )
            .unwrap();
        let target = TargetKey {
            host: "kafka.test".into(),
            port: 9092,
        };
        let original: RecordedKafkaProduce = serde_json::from_value(produce).unwrap();
        let actual = decode_record(
            original.topic,
            original.key,
            original.headers,
            original.value,
            0,
        )
        .unwrap();
        let reservation = state
            .reserve_produce(None, &target, std::slice::from_ref(&actual), false)
            .unwrap();
        assert!(
            state
                .reserve_produce(None, &target, std::slice::from_ref(&actual), false)
                .is_none()
        );
        state.commit_produce(reservation);
        assert!(
            state
                .reserve_produce(None, &target, &[actual], false)
                .is_none()
        );
        let topics = BTreeSet::from(["items".to_string()]);
        let reservation = state.reserve_fetch(None, &target, &topics).unwrap();
        assert_eq!(
            reservation.records[0].value.as_deref(),
            Some(b"delivered".as_slice())
        );
        assert_eq!(
            reservation.records[0].headers[0].value.as_deref(),
            Some(b"header".as_slice())
        );
        state.commit_fetch(reservation);
        assert!(state.reserve_fetch(None, &target, &topics).is_none());
    }
}
