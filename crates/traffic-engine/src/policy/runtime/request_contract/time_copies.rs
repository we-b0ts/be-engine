//! Runtime commits delivered read provenance after the protocol write succeeds.
use super::*;
use crate::value_contract::{
    json::VerifiedTimeCopy,
    time_copies::{TimeCopyLookup, TimeCopyRecord},
};

impl RequestContracts {
    pub(crate) fn delivered_time_copies(
        &self,
        case: &str,
    ) -> crate::value_contract::time_copies::DeliveredTimeCopies {
        self.values
            .time_copies
            .lock()
            .expect("time copies")
            .delivered_copies(case)
    }
    pub(crate) fn has_time_copies(&self, case: &str) -> bool {
        self.values
            .time_copies
            .lock()
            .expect("time copies")
            .has_case(case)
    }
    pub(crate) fn clear_time_copies(&self, case: &str) {
        self.values
            .time_copies
            .lock()
            .expect("time copies")
            .begin_case(case);
    }
    #[allow(dead_code)]
    pub(crate) fn record_time_copies(
        &self,
        case: &str,
        records: Vec<TimeCopyRecord>,
        clocks: crate::value_contract::time::ClockPair,
    ) -> Result<()> {
        let mut store = self.values.time_copies.lock().expect("time copies");
        store.set_record_clocks(clocks);
        store.record_batch(case, records)
    }
    #[allow(dead_code)]
    pub(super) fn time_copy_deliveries(
        &self,
        case: &str,
        lookups: Vec<TimeCopyLookup>,
        clocks: crate::value_contract::time::ClockPair,
    ) -> Result<Vec<(serde_json::Value, VerifiedTimeCopy)>> {
        let mut store = self.values.time_copies.lock().expect("time copies");
        store.set_lookup_clocks(clocks);
        lookups
            .iter()
            .filter_map(|lookup| store.delivery_prepared(case, lookup).transpose())
            .collect()
    }
    #[allow(dead_code)]
    /// Callers prepare hashes and paths without holding the store mutex.
    pub(crate) fn time_copy_proofs(
        &self,
        case: &str,
        lookups: Vec<TimeCopyLookup>,
        clocks: crate::value_contract::time::ClockPair,
    ) -> Vec<VerifiedTimeCopy> {
        if lookups.is_empty() {
            return vec![];
        }
        let mut store = self.values.time_copies.lock().expect("time copies");
        store.set_lookup_clocks(clocks);
        lookups
            .iter()
            .filter_map(|lookup| store.proof_prepared(case, lookup))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FieldContract, RedisContainer};
    use serde_json::json;

    #[test]
    fn ended_case_releases_only_its_provenance_and_shared_owners_see_cleanup() {
        let owner = RequestContracts::default();
        let clone = owner.clone();
        let field: FieldContract = serde_json::from_value(json!({
            "kind":"time", "format":"unix_seconds", "relation":"preserve_offset"
        }))
        .unwrap();
        let time = field.time().unwrap();
        let position = traffic_protocol_redis::values::ValuePosition {
            host: "cache.test",
            port: 6379,
            database: 0,
            key: b"task:1",
            container: RedisContainer::String,
            hash_field: None,
        }
        .origin();
        for case in ["case-a", "case-b"] {
            owner
                .record_time_copies(
                    case,
                    vec![
                        TimeCopyRecord::new_time(
                            &time,
                            position,
                            position,
                            "/t",
                            "/t",
                            &json!(10),
                            &json!(10),
                        )
                        .unwrap(),
                    ],
                    crate::value_contract::time::ClockPair {
                        source: chrono::DateTime::from_timestamp(1, 0),
                        target: chrono::DateTime::from_timestamp(2, 0),
                    },
                )
                .unwrap();
        }
        owner.clear_time_copies("case-a");
        assert!(!clone.has_time_copies("case-a"));
        assert!(clone.has_time_copies("case-b"));
        owner.clear_time_copies("case-b");
        assert!(!owner.has_time_copies("case-b"));
    }
}
