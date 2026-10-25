//! Source witness production delegates protocol value and framing semantics to Memcached.
use super::*;

impl RequestContracts {
    pub(super) fn observe_unified_memcached_source(&self, case: &str, event: &Value) -> Result<()> {
        crate::replay::memcached::contracts::source_observation(self, case, event)
    }
}
