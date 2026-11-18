//! Observe immutable Source messages through installed native providers.
use super::*;

impl RequestContracts {
    pub fn observe_source(
        &self,
        case: &str,
        bytes: &[u8],
        index: Option<&crate::dependency_index::FileIndex>,
    ) -> Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        self.register_source_records(case, bytes, index)?;
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let event: Value = serde_json::from_slice(line)?;
            if crate::dependency::observation::is_case_event(&event) {
                self.observe_plan_fact(case, &event);
            }
        }
        Ok(())
    }
}
