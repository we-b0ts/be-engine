//! Physical occurrences supply scope contexts to registered observation owners.
use super::Comparison;

impl Comparison {
    pub fn scope_observations(&mut self, context: &str) {
        self.observations.scope(context);
    }

    pub fn scope_schema_clocks(&mut self, occurrence: usize) {
        self.scope_observations(&format!("physical-value:{occurrence}"));
    }

    pub fn scope_schema_clocks_in(&mut self, context: &str) {
        self.scope_observations(context);
    }
}
