//! Managed secret access supplied to native evidence projections.
use super::*;
use std::{borrow::Cow, sync::OnceLock};

pub struct SourceSecrets<'a> {
    path: &'a Path,
    cipher: OnceLock<RequestHeaderCipher>,
}
impl<'a> SourceSecrets<'a> {
    pub fn new(path: &'a Path) -> Self {
        Self {
            path,
            cipher: OnceLock::new(),
        }
    }
}
impl traffic_protocol::evidence::EvidenceSecrets for SourceSecrets<'_> {
    fn unseal_text<'a>(&self, label: &str, value: &'a str) -> Result<Cow<'a, str>> {
        if !value.starts_with("traffic-e2e:enc:") {
            return Ok(Cow::Borrowed(value));
        }
        if self.cipher.get().is_none() {
            let cipher = RequestHeaderCipher::from_environment_or_request_path(Some(self.path))?;
            let _ = self.cipher.set(cipher);
        }
        let plaintext = self
            .cipher
            .get()
            .context("Source evidence cipher is absent")?
            .decrypt(label, value)?;
        let value = String::from_utf8(plaintext)
            .unwrap_or_else(|error| STANDARD.encode(error.into_bytes()));
        Ok(Cow::Owned(value))
    }
}
