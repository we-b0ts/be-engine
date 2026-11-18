//! Installed content evidence for native payload bindings.
pub use traffic_policy_content::protobuf::payload_pair;
pub mod unordered_evidence {
    use traffic_policy_schema::response::{ProtobufFieldPath, ProtobufRepeatedElementType};
    #[allow(dead_code)]
    pub fn candidates(
        expected: &[u8],
        actual: &[u8],
    ) -> Vec<(ProtobufFieldPath, Vec<ProtobufRepeatedElementType>)> {
        traffic_policy_content::protobuf::unordered_evidence::candidates(
            traffic_extensions::policies(),
            expected,
            actual,
        )
    }
}
