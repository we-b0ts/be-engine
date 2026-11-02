//! Authenticate plaintext request candidates independently of payload encoding.
use super::*;
use hmac::{Hmac, Mac};

fn signature_mac(context: &Path, label: &str, bytes: &[u8]) -> Result<Hmac<Sha256>> {
    let key = crate::request_headers::managed_evidence_key(context)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("invalid evidence signing key"))?;
    mac.update(b"traffic-e2e/evidence-signature/v1\0");
    mac.update(label.as_bytes());
    mac.update(&[0]);
    mac.update(bytes);
    Ok(mac)
}

pub(crate) fn sign(context: &Path, label: &str, bytes: &[u8]) -> Result<String> {
    Ok(STANDARD.encode(
        signature_mac(context, label, bytes)?
            .finalize()
            .into_bytes(),
    ))
}

pub(crate) fn verify(context: &Path, label: &str, bytes: &[u8], signature: &str) -> Result<()> {
    signature_mac(context, label, bytes)?
        .verify_slice(&STANDARD.decode(signature)?)
        .map_err(|_| anyhow::anyhow!("request witness authentication failed"))
}
