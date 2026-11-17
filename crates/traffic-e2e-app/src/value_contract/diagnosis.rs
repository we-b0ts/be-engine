//! Application composition supplies installed codecs to original-value diagnosis.
use serde_json::Value;
pub(crate) fn at_pointer(source: &[u8], target: &[u8], pointer: &str) -> Value {
    traffic_policy_value::diagnosis::bodies::at_pointer(
        traffic_extensions::codecs(),
        source,
        target,
        pointer,
    )
}
pub(crate) fn differences(source: &[u8], target: &[u8], offset: usize) -> Value {
    traffic_policy_value::diagnosis::bodies::differences(
        traffic_extensions::codecs(),
        source,
        target,
        offset,
    )
}
