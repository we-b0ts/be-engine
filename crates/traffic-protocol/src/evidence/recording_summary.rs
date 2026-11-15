//! Open native recording summaries with framework-owned event inclusion.
use super::*;

pub struct RecordingSummaries {
    registry: EvidenceRegistry,
    accumulators: BTreeMap<usize, Box<dyn RecordingSummary>>,
}

impl RecordingSummaries {
    pub fn new(registry: EvidenceRegistry) -> Self {
        Self {
            registry,
            accumulators: BTreeMap::new(),
        }
    }

    pub fn observe(&mut self, event: &Value) -> bool {
        let Some(index) = event["event_type"]
            .as_str()
            .and_then(|kind| self.registry.events.get(kind))
            .copied()
        else {
            return true;
        };
        let adapter = &self.registry.registrations[index].adapter;
        if !adapter.include_in_recording_summary(event) {
            return false;
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = self.accumulators.entry(index)
            && let Some(accumulator) = adapter.recording_summary()
        {
            entry.insert(accumulator);
        }
        if let Some(accumulator) = self.accumulators.get_mut(&index) {
            accumulator.observe(event);
        }
        true
    }

    pub fn finish(self) -> Result<BTreeMap<String, Value>> {
        let mut fields = BTreeMap::new();
        for accumulator in self.accumulators.into_values() {
            for (name, value) in accumulator.finish()? {
                ensure!(
                    ![
                        "version",
                        "source",
                        "total_events",
                        "event_types",
                        "parse_errors"
                    ]
                    .contains(&name.as_str()),
                    "native recording summary shadows framework counters"
                );
                ensure!(
                    fields.insert(name, value).is_none(),
                    "native recording summaries have overlapping owners"
                );
            }
        }
        Ok(fields)
    }
}
