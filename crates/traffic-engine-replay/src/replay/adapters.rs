pub use traffic_model::recording::ProtocolRef as RecordedReference;
use traffic_protocol::ProtocolId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolExchange {
    pub inventory: ProtocolId,
    pub index: usize,
}
