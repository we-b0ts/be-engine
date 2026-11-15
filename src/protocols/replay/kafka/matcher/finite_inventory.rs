//! Finite Kafka effects retain semantic identities and wait on native I/O completion.
use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) enum FiniteExchange {
    Produce(usize),
    Fetch(usize),
    Delivery(usize),
}

impl KafkaReplayState {
    pub(crate) fn finite_exchanges(
        &self,
        case: &str,
    ) -> Result<BTreeMap<(&'static str, Uuid, u64), FiniteExchange>> {
        let mut result = BTreeMap::new();
        for (i, e) in
            self.produces.iter().enumerate().filter(|(_, e)| {
                e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case)
            })
        {
            if let Some(sequence) = e.record_sequence {
                anyhow::ensure!(
                    result
                        .insert(
                            ("produce", e.connection_id, sequence),
                            FiniteExchange::Produce(i)
                        )
                        .is_none(),
                    "ambiguous finite Kafka produce reference"
                );
            }
        }
        for (i, e) in
            self.fetches.iter().enumerate().filter(|(_, e)| {
                e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case)
            })
        {
            anyhow::ensure!(
                result
                    .insert(
                        ("fetch", e.connection_id, e.sequence),
                        FiniteExchange::Fetch(i)
                    )
                    .is_none(),
                "ambiguous finite Kafka fetch reference"
            );
        }
        for (i, e) in
            self.deliveries.iter().enumerate().filter(|(_, e)| {
                e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case)
            })
        {
            if let Some(sequence) = e.sequence {
                anyhow::ensure!(
                    result
                        .insert(
                            ("delivery", e.connection_id, sequence),
                            FiniteExchange::Delivery(i)
                        )
                        .is_none(),
                    "ambiguous finite Kafka delivery reference"
                );
            }
        }
        Ok(result)
    }
    pub(crate) fn finite_exchange_status(
        &self,
        exchange: FiniteExchange,
    ) -> Option<ReplayExchangeStatus> {
        match exchange {
            FiniteExchange::Produce(i) => self.produces.get(i).map(|e| e.status),
            FiniteExchange::Fetch(i) => self.fetches.get(i).map(|e| e.status),
            FiniteExchange::Delivery(i) => self.deliveries.get(i).map(|e| e.status),
        }
    }
}

impl KafkaReplayState {
    pub(crate) fn startup_counts(&mut self, close: bool) -> traffic_replay::StartupCounts {
        let mut counts = traffic_replay::StartupCounts::default();
        for e in &mut self.produces {
            counts.observe(e.source, &mut e.status, true, close);
        }
        for e in &mut self.fetches {
            counts.observe(e.source, &mut e.status, true, close);
        }
        for e in &mut self.deliveries {
            counts.observe(e.source, &mut e.status, true, close);
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finite_effects_wait_for_native_delivery_and_never_borrow_another_case() {
        let connection = Uuid::new_v4();
        let mut state = KafkaReplayState::default();
        let mut targets = BTreeMap::new();
        let record = json!({"connection_id":connection,"request_sequence":1,"sequence":11,"target_host":"kafka.test","target_port":9092,"topic":"jobs","key":null,"headers":[],"value":{"encoding":"utf8","data":"payload","truncated":false},"result":"accepted","outcome":"response","duration_ms":0,"replay_safe":true});
        state
            .register_produce(
                serde_json::from_value(record).unwrap(),
                ReplaySource::Case,
                Some("owner"),
                &mut targets,
            )
            .unwrap();
        let fetch = json!({"connection_id":connection,"sequence":2,"target_host":"kafka.test","target_port":9092,"topics":["jobs"],"outcome":"response","duration_ms":0,"replay_safe":true});
        state
            .register_fetch(
                serde_json::from_value(fetch).unwrap(),
                ReplaySource::Case,
                Some("owner"),
                &mut targets,
            )
            .unwrap();
        for sequence in [21, 22] {
            let delivery = json!({"connection_id":connection,"fetch_sequence":2,"sequence":sequence,"target_host":"kafka.test","target_port":9092,"topic":"jobs","key":null,"headers":[],"value":{"encoding":"utf8","data":"payload","truncated":false},"message_timestamp_ms":0,"replay_safe":true});
            state
                .register_delivery(
                    serde_json::from_value(delivery).unwrap(),
                    ReplaySource::Case,
                    Some("owner"),
                    &mut targets,
                )
                .unwrap();
        }
        let refs = state.finite_exchanges("owner").unwrap();
        assert_eq!(
            refs.len(),
            4,
            "physical fetch and its two delivery effects stay distinct"
        );
        assert!(state.finite_exchanges("other").unwrap().is_empty());
        let target = TargetKey {
            host: "kafka.test".into(),
            port: 9092,
        };
        let produced = state.produces[0].record.clone();
        let reservation = state
            .reserve_produce(Some("owner"), &target, &[produced], false)
            .unwrap();
        assert_eq!(
            state.finite_exchange_status(refs[&("produce", connection, 11)]),
            Some(ReplayExchangeStatus::Responding)
        );
        state.commit_produce(reservation);
        assert_eq!(
            state.finite_exchange_status(refs[&("produce", connection, 11)]),
            Some(ReplayExchangeStatus::Consumed)
        );
        let reservation = state
            .reserve_fetch(Some("owner"), &target, &BTreeSet::from(["jobs".into()]))
            .unwrap();
        for sequence in [21, 22] {
            assert_eq!(
                state.finite_exchange_status(refs[&("delivery", connection, sequence)]),
                Some(ReplayExchangeStatus::Responding)
            );
        }
        state.commit_fetch(reservation);
        assert!(
            refs.values()
                .all(|reference| state.finite_exchange_status(*reference)
                    == Some(ReplayExchangeStatus::Consumed))
        );
    }
}
