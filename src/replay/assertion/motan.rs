use anyhow::{Context, Result, bail, ensure};
use motan_protocol::{
    DecodeStatus, Limits, META_PROCESS_TIME, MessageKind, ProtocolVersion, decode_frame,
};

const MOTAN2_PROXY_FLAG: u8 = 0x02;

pub(super) struct ComparableResponseFrame {
    encoded: Vec<u8>,
    body_offset: usize,
}

impl ComparableResponseFrame {
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
    let mut encoded = frame
        .encode()
        .map(|encoded| encoded.to_vec())
        .with_context(|| format!("failed to normalize {label} Motan response frame"))?;
    if frame.version == ProtocolVersion::Motan2 {
        // PROXY describes how a request reached the service. The observed Java
        // source may clear it on the response while another compatible server
        // reflects it, so it is not response-semantic evidence.
        encoded[2] &= !MOTAN2_PROXY_FLAG;
    }
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

#[cfg(test)]
mod tests {
    use motan_protocol::FrameBuilder;

    use super::*;

    #[test]
    fn motan2_response_proxy_flag_does_not_affect_comparison() {
        let source = FrameBuilder::response(42)
            .body("response")
            .encode()
            .unwrap();
        let target = FrameBuilder::response(42)
            .proxy(true)
            .body("response")
            .encode()
            .unwrap();

        let source = comparable_response_frame(&source, "source response").unwrap();
        let target = comparable_response_frame(&target, "target response").unwrap();

        assert_eq!(source.encoded, target.encoded);
        assert_eq!(source.carrier(), target.carrier());
        assert_eq!(source.body(), target.body());
    }
}
