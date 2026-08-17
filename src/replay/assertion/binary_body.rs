use anyhow::{Result, ensure};

const SIMPLE_BYTE_ARRAY: u8 = 3;

pub(super) fn extract_simple_payload(body: &[u8]) -> Result<&[u8]> {
    ensure!(
        body.len() >= 5 && body[0] == SIMPLE_BYTE_ARRAY,
        "Motan body is not a simple byte-array envelope"
    );
    let declared = u32::from_be_bytes(body[1..5].try_into().expect("four-byte length")) as usize;
    ensure!(
        declared == body.len() - 5,
        "Motan simple byte-array length does not match its payload"
    );
    Ok(&body[5..])
}
