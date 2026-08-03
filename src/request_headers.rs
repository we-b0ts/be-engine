use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hyper::HeaderMap;
use serde_json::Value;

pub(crate) const ENCRYPTION_KEY_ENV: &str = "TRAFFIC_E2E_ENCRYPTION_KEY_B64";

const ENCRYPTED_VALUE_PREFIX: &str = "traffic-e2e:enc:v1:aes-256-gcm:";
const AES_256_KEY_BYTES: usize = 32;
const AES_GCM_NONCE_BYTES: usize = 12;

type HeaderSnapshot = BTreeMap<String, Vec<String>>;

#[derive(Clone)]
pub(crate) struct RequestHeaderCapture {
    encrypted_names: Arc<HashSet<String>>,
    redacted_names: Arc<HashSet<String>>,
    cipher: Option<Arc<RequestHeaderCipher>>,
}

impl RequestHeaderCapture {
    pub(crate) fn from_environment(
        encrypted_names: &[String],
        redacted_names: &[String],
    ) -> Result<Self> {
        let encrypted_names = normalize_names(encrypted_names);
        let cipher = if encrypted_names.is_empty() {
            None
        } else {
            Some(Arc::new(RequestHeaderCipher::from_environment()?))
        };
        Ok(Self {
            encrypted_names: Arc::new(encrypted_names),
            redacted_names: Arc::new(normalize_names(redacted_names)),
            cipher,
        })
    }

    pub(crate) fn capture(&self, headers: &HeaderMap) -> Result<HeaderSnapshot> {
        let mut out = HeaderSnapshot::new();
        for (name, value) in headers {
            let name = name.as_str().to_ascii_lowercase();
            let rendered = if self.encrypted_names.contains(&name) {
                self.cipher
                    .as_ref()
                    .context("request header encryption key is unavailable")?
                    .encrypt(&name, value.as_bytes())?
            } else if self.redacted_names.contains(&name) {
                "<redacted>".to_string()
            } else {
                value
                    .to_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|_| STANDARD.encode(value.as_bytes()))
            };
            out.entry(name).or_default().push(rendered);
        }
        Ok(out)
    }

    #[cfg(test)]
    fn with_key(
        encrypted_names: &[String],
        redacted_names: &[String],
        key: &[u8; AES_256_KEY_BYTES],
    ) -> Self {
        Self {
            encrypted_names: Arc::new(normalize_names(encrypted_names)),
            redacted_names: Arc::new(normalize_names(redacted_names)),
            cipher: Some(Arc::new(RequestHeaderCipher::from_key(key))),
        }
    }
}

pub(crate) fn decrypt_request_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let raw = std::fs::read(path)
        .with_context(|| format!("failed to read recorded request {}", path.display()))?;
    decrypt_request_payload(&raw)
        .with_context(|| format!("failed to decrypt recorded request {}", path.display()))
}

pub(crate) fn load_request_file(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path)
        .with_context(|| format!("failed to read recorded request {}", path.display()))?;
    Ok(decrypt_request_payload(&raw)
        .with_context(|| format!("failed to decrypt recorded request {}", path.display()))?
        .unwrap_or(raw))
}

pub(crate) fn validate_request_file(path: &Path) -> Result<()> {
    let _ = decrypt_request_file(path)?;
    Ok(())
}

fn decrypt_request_payload(raw: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut request: Value =
        serde_json::from_slice(raw).context("recorded request is not valid JSON")?;
    let Some(headers) = request.get_mut("headers").and_then(Value::as_object_mut) else {
        return Ok(None);
    };
    if !headers.values().any(contains_encrypted_value) {
        return Ok(None);
    }

    let cipher = RequestHeaderCipher::from_environment()?;
    decrypt_headers(headers, &cipher)?;
    let mut payload =
        serde_json::to_vec_pretty(&request).context("failed to serialize decrypted request")?;
    payload.push(b'\n');
    Ok(Some(payload))
}

fn decrypt_headers(
    headers: &mut serde_json::Map<String, Value>,
    cipher: &RequestHeaderCipher,
) -> Result<()> {
    for (name, values) in headers {
        let values = values
            .as_array_mut()
            .with_context(|| format!("recorded request header {name:?} must be an array"))?;
        for value in values {
            let Some(encoded) = value.as_str() else {
                bail!("recorded request header {name:?} value must be a string");
            };
            if !encoded.starts_with("traffic-e2e:enc:") {
                continue;
            }
            let plaintext = cipher.decrypt(&name.to_ascii_lowercase(), encoded)?;
            let plaintext = String::from_utf8(plaintext)
                .with_context(|| format!("decrypted request header {name:?} is not valid UTF-8"))?;
            *value = Value::String(plaintext);
        }
    }
    Ok(())
}

fn contains_encrypted_value(value: &Value) -> bool {
    value.as_array().is_some_and(|values| {
        values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| value.starts_with("traffic-e2e:enc:"))
        })
    })
}

fn normalize_names(names: &[String]) -> HashSet<String> {
    names.iter().map(|name| name.to_ascii_lowercase()).collect()
}

struct RequestHeaderCipher {
    cipher: Aes256Gcm,
}

impl RequestHeaderCipher {
    fn from_environment() -> Result<Self> {
        let encoded = std::env::var(ENCRYPTION_KEY_ENV).with_context(|| {
            format!("{ENCRYPTION_KEY_ENV} is required for encrypted request headers")
        })?;
        Self::from_encoded_key(&encoded)
    }

    fn from_encoded_key(encoded: &str) -> Result<Self> {
        ensure!(
            !encoded.trim().is_empty(),
            "{ENCRYPTION_KEY_ENV} must not be empty"
        );
        let key = STANDARD
            .decode(encoded.trim())
            .with_context(|| format!("{ENCRYPTION_KEY_ENV} must contain valid Base64"))?;
        ensure!(
            key.len() == AES_256_KEY_BYTES,
            "{ENCRYPTION_KEY_ENV} must decode to exactly {AES_256_KEY_BYTES} bytes"
        );
        let key: [u8; AES_256_KEY_BYTES] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("validated AES-256 key length changed unexpectedly"))?;
        Ok(Self::from_key(&key))
    }

    fn from_key(key: &[u8; AES_256_KEY_BYTES]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(key).expect("AES-256 key has a fixed valid length"),
        }
    }

    fn encrypt(&self, header_name: &str, plaintext: &[u8]) -> Result<String> {
        let mut nonce = [0_u8; AES_GCM_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|error| {
            anyhow::anyhow!("failed to generate request header encryption nonce: {error}")
        })?;
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: header_name.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt request header"))?;
        Ok(format!(
            "{ENCRYPTED_VALUE_PREFIX}{}:{}",
            STANDARD.encode(nonce),
            STANDARD.encode(ciphertext)
        ))
    }

    fn decrypt(&self, header_name: &str, encoded: &str) -> Result<Vec<u8>> {
        let payload = encoded.strip_prefix(ENCRYPTED_VALUE_PREFIX).with_context(
            || "unsupported encrypted request header format; expected traffic-e2e AES-256-GCM v1",
        )?;
        let (nonce, ciphertext) = payload
            .split_once(':')
            .context("encrypted request header is missing its ciphertext")?;
        let nonce = STANDARD
            .decode(nonce)
            .context("encrypted request header nonce is not valid Base64")?;
        ensure!(
            nonce.len() == AES_GCM_NONCE_BYTES,
            "encrypted request header nonce must contain {AES_GCM_NONCE_BYTES} bytes"
        );
        let ciphertext = STANDARD
            .decode(ciphertext)
            .context("encrypted request header payload is not valid Base64")?;
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: header_name.as_bytes(),
                },
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "encrypted request header authentication failed; verify {ENCRYPTION_KEY_ENV}"
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use hyper::header::{AUTHORIZATION, HeaderValue};

    use super::*;

    const KEY: [u8; AES_256_KEY_BYTES] = [7; AES_256_KEY_BYTES];

    #[test]
    fn encrypts_configured_headers_case_insensitively_and_prefers_encryption() {
        let capture = RequestHeaderCapture::with_key(
            &["Authorization".to_string()],
            &["authorization".to_string()],
            &KEY,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("OAuth2 sensitive-token"),
        );

        let stored = capture.capture(&headers).unwrap();
        let encrypted = &stored["authorization"][0];

        assert!(encrypted.starts_with(ENCRYPTED_VALUE_PREFIX));
        assert!(!encrypted.contains("sensitive-token"));
        assert_ne!(encrypted, "<redacted>");
    }

    #[test]
    fn decrypts_a_versioned_request_header_envelope() {
        let cipher = RequestHeaderCipher::from_key(&KEY);
        let encrypted = cipher
            .encrypt("authorization", b"OAuth2 sensitive-token")
            .unwrap();
        let mut request = serde_json::json!({
            "method": "GET",
            "uri": "/resource",
            "headers": {
                "authorization": [encrypted],
                "accept": ["application/json"]
            }
        });

        decrypt_headers(request["headers"].as_object_mut().unwrap(), &cipher).unwrap();

        assert_eq!(
            request["headers"]["authorization"][0],
            "OAuth2 sensitive-token"
        );
        assert_eq!(request["headers"]["accept"][0], "application/json");
    }

    #[test]
    fn rejects_wrong_keys_and_invalid_key_material() {
        let encrypted = RequestHeaderCipher::from_key(&KEY)
            .encrypt("authorization", b"secret")
            .unwrap();
        let wrong = RequestHeaderCipher::from_key(&[8; AES_256_KEY_BYTES]);

        assert!(wrong.decrypt("authorization", &encrypted).is_err());
        assert!(RequestHeaderCipher::from_encoded_key("").is_err());
        assert!(RequestHeaderCipher::from_encoded_key("not-base64").is_err());
        assert!(RequestHeaderCipher::from_encoded_key(&STANDARD.encode([0_u8; 31])).is_err());
    }

    #[test]
    fn uses_a_fresh_nonce_for_each_value() {
        let cipher = RequestHeaderCipher::from_key(&KEY);

        let first = cipher.encrypt("authorization", b"same").unwrap();
        let second = cipher.encrypt("authorization", b"same").unwrap();

        assert_ne!(first, second);
    }
}
