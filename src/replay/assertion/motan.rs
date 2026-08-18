use anyhow::{Context, Result, bail, ensure};
use motan_protocol::{
    DecodeStatus, Limits, META_PROCESS_TIME, MessageKind, ProtocolVersion, decode_frame,
};

pub(super) struct ComparableResponseFrame {
    encoded: Vec<u8>,
    body_offset: usize,
}

impl ComparableResponseFrame {
    pub(super) fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub(super) fn body(&self) -> &[u8] {
        &self.encoded[self.body_offset..]
    }

    pub(super) fn carrier(&self) -> &[u8] {
        &self.encoded[..self.body_offset]
    }
}

pub(super) fn comparable_response_frame(
    raw: &[u8],
    label: &str,
) -> Result<ComparableResponseFrame> {
    let capacity = raw.len().max(32);
    let limits = Limits {
        max_frame_bytes: capacity,
        max_metadata_bytes: capacity,
        max_body_bytes: capacity,
    };
    let DecodeStatus::Complete(mut frame) = decode_frame(raw, limits)
        .with_context(|| format!("{label} contains an invalid Motan response frame"))?
    else {
        bail!("{label} contains an incomplete Motan response frame");
    };
    ensure!(
        frame.raw().len() == raw.len(),
        "{label} contains trailing bytes after its Motan response frame"
    );
    ensure!(
        matches!(
            frame.version,
            ProtocolVersion::Motan1 | ProtocolVersion::Motan2
        ) && frame.kind == MessageKind::Response,
        "{label} does not contain a Motan response frame"
    );

    while frame.metadata.remove(META_PROCESS_TIME).is_some() {}
    let body_len = frame.body.len();
    let encoded = frame
        .encode()
        .map(|encoded| encoded.to_vec())
        .with_context(|| format!("failed to normalize {label} Motan response frame"))?;
    let body_offset = encoded
        .len()
        .checked_sub(body_len)
        .context("normalized Motan response body exceeds its frame")?;
    ensure!(
        encoded[body_offset..] == frame.body,
        "normalized {label} Motan response body is not at the end of its frame"
    );
    Ok(ComparableResponseFrame {
        encoded,
        body_offset,
    })
}
