use traffic_protocol::{Peer, Probe, Recognition};

pub fn recognize(probe: Probe<'_>) -> Recognition {
    if probe.peer != Peer::Server {
        return Recognition::Reject;
    }
    let bytes = probe.bytes;
    if bytes.len() < 5 {
        return Recognition::NeedMore;
    }
    let length =
        usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16);
    if length > 0 && bytes[3] == 0 && bytes[4] == 0x0a {
        Recognition::Match
    } else {
        Recognition::Reject
    }
}
