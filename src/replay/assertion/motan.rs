use anyhow::{Context, Result, bail, ensure};
use motan_protocol::{
    DecodeStatus, Limits, META_PROCESS_TIME, MessageKind, ProtocolVersion, decode_frame,
};

pub(super) fn comparable_response_frame(raw: &[u8], label: &str) -> Result<Vec<u8>> {
    let capacity = raw.len().max(32);
    let limits = Limits {
        max_frame_bytes: capacity,
        max_metadata_bytes: capacity,
        max_body_bytes: capacity,
    };
    let DecodeStatus::Complete(mut frame) = decode_frame(raw, limits)
        .with_context(|| format!("{label} contains an invalid Motan2 response frame"))?
    else {
        bail!("{label} contains an incomplete Motan2 response frame");
    };
    ensure!(
        frame.raw().len() == raw.len(),
        "{label} contains trailing bytes after its Motan2 response frame"
    );
    ensure!(
        frame.version == ProtocolVersion::Motan2 && frame.kind == MessageKind::Response,
        "{label} does not contain a Motan2 response frame"
    );

    while frame.metadata.remove(META_PROCESS_TIME).is_some() {}
    frame
        .encode()
        .map(|encoded| encoded.to_vec())
        .with_context(|| format!("failed to normalize {label} Motan2 response frame"))
}
