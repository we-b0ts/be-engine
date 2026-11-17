//! Installed content evidence for native payload bindings.
pub(crate) use traffic_policy_content::protobuf::payload_pair;
pub(crate) mod unordered_evidence {
    use traffic_policy_schema::response::{ProtobufFieldPath, ProtobufRepeatedElementType};
    #[allow(dead_code)]
    pub(crate) fn candidates(
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
