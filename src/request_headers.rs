use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hyper::HeaderMap;
use serde_json::Value;

pub(crate) mod evidence;

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
    pub(crate) fn with_key(
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
    let (_, decrypted) = read_request_file_parts(path)?;
    Ok(decrypted)
}

pub(crate) fn load_request_file(path: &Path) -> Result<Vec<u8>> {
    let (raw, decrypted) = read_request_file_parts(path)?;
    Ok(decrypted.unwrap_or(raw))
}

pub(crate) fn read_request_file_parts(path: &Path) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let raw = std::fs::read(path)
        .with_context(|| format!("failed to read recorded request {}", path.display()))?;
    let decrypted = decrypt_request_payload(&raw, Some(path))
        .with_context(|| format!("failed to decrypt recorded request {}", path.display()))?;
    Ok((raw, decrypted))
}

pub(crate) fn validate_request_file(path: &Path) -> Result<()> {
    let _ = decrypt_request_file(path)?;
    Ok(())
}

/// Decode dependency headers using the same managed key as inbound requests.
/// Return protected names so diagnostic projections never reveal encrypted or
/// explicitly redacted values from either side of a comparison.
pub(crate) fn decrypt_dependency_headers(
    headers: &mut HeaderSnapshot,
    path: &Path,
) -> Result<BTreeSet<String>> {
    let protected = headers
        .iter()
        .filter(|(_, values)| {
            values
                .iter()
                .any(|value| value.starts_with("traffic-e2e:enc:") || value == "<redacted>")
        })
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if !headers
        .values()
        .flatten()
        .any(|value| value.starts_with("traffic-e2e:enc:"))
    {
        return Ok(protected);
    }
    let cipher = RequestHeaderCipher::from_environment_or_request_path(Some(path))?;
    for (name, values) in headers {
        for value in values {
            if value.starts_with("traffic-e2e:enc:") {
                let plaintext = cipher.decrypt(&name.to_ascii_lowercase(), value)?;
                *value = String::from_utf8(plaintext.clone())
                    .unwrap_or_else(|_| STANDARD.encode(plaintext));
            }
        }
    }
    Ok(protected)
}

fn decrypt_request_payload(raw: &[u8], request_path: Option<&Path>) -> Result<Option<Vec<u8>>> {
    let mut request: Value =
        serde_json::from_slice(raw).context("recorded request is not valid JSON")?;
    let mut changed = if let Some(path) = request_path {
        crate::interaction::private::decrypt_request(&mut request, path)?
    } else {
        ensure!(
            request.get("private_uri").is_none() && request.get("private_headers").is_none(),
            "private interaction request requires its evidence path"
        );
        false
    };
    changed |= decrypt_header_snapshot(request.get_mut("headers"), request_path)?;
    if let Some(actions) = request
        .pointer_mut("/interaction/actions")
        .and_then(Value::as_array_mut)
    {
        for action in actions {
            if action.pointer("/action/kind").and_then(Value::as_str) == Some("upgrade") {
                changed |=
                    decrypt_header_snapshot(action.pointer_mut("/action/headers"), request_path)?;
            }
        }
    }
    if !changed {
        return Ok(None);
    }
    let mut payload =
        serde_json::to_vec_pretty(&request).context("failed to serialize decrypted request")?;
    payload.push(b'\n');
    Ok(Some(payload))
}

fn decrypt_header_snapshot(value: Option<&mut Value>, path: Option<&Path>) -> Result<bool> {
    let Some(headers) = value.and_then(Value::as_object_mut) else {
        return Ok(false);
    };
    if !headers.values().any(contains_encrypted_value) {
        return Ok(false);
    }
    decrypt_headers(
        headers,
        &RequestHeaderCipher::from_environment_or_request_path(path)?,
    )?;
    Ok(true)
}

/// Decode a caller-owned immutable view without creating plaintext evidence files.
pub(crate) fn decrypt_request_bytes(raw: &[u8], path: &Path) -> Result<Option<Vec<u8>>> {
    decrypt_request_payload(raw, Some(path))
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

pub(crate) fn has_encrypted_request_headers(request: &Value) -> bool {
    let encrypted = |headers: Option<&Value>| {
        headers
            .and_then(Value::as_object)
            .is_some_and(|headers| headers.values().any(contains_encrypted_value))
    };
    request.get("private_headers").is_some()
        || encrypted(request.get("headers"))
        || request
            .pointer("/interaction/actions")
            .and_then(Value::as_array)
            .is_some_and(|actions| {
                actions.iter().any(|action| {
                    action.pointer("/action/kind").and_then(Value::as_str) == Some("upgrade")
                        && encrypted(action.pointer("/action/headers"))
                })
            })
}

fn normalize_names(names: &[String]) -> HashSet<String> {
    names.iter().map(|name| name.to_ascii_lowercase()).collect()
}

struct RequestHeaderCipher {
    cipher: Aes256Gcm,
    key: [u8; AES_256_KEY_BYTES],
}

impl RequestHeaderCipher {
    fn from_environment() -> Result<Self> {
        let encoded = std::env::var(ENCRYPTION_KEY_ENV).with_context(|| {
            format!("{ENCRYPTION_KEY_ENV} is required for encrypted request headers")
        })?;
        Self::from_encoded_key(&encoded)
    }

    fn from_environment_or_request_path(request_path: Option<&Path>) -> Result<Self> {
        match std::env::var(ENCRYPTION_KEY_ENV) {
            Ok(encoded) => Self::from_encoded_key(&encoded),
            Err(std::env::VarError::NotUnicode(_)) => {
                bail!("{ENCRYPTION_KEY_ENV} must contain valid UTF-8")
            }
            Err(std::env::VarError::NotPresent) => {
                let request_path = request_path.context(format!(
                    "{ENCRYPTION_KEY_ENV} is required for encrypted request headers"
                ))?;
                let key_path = project_encryption_key_path(request_path).context(format!(
                    "{ENCRYPTION_KEY_ENV} is missing and {request_path:?} is not under an initialized .traffic-e2e/local directory"
                ))?;
                let encoded = std::fs::read_to_string(&key_path).with_context(|| {
                    format!(
                        "failed to read managed request-header encryption key {}",
                        key_path.display()
                    )
                })?;
                Self::from_encoded_key(&encoded)
            }
        }
    }

    fn from_encoded_key(encoded: &str) -> Result<Self> {
        ensure!(
            !encoded.is_empty(),
            "{ENCRYPTION_KEY_ENV} must not be empty"
        );
        let key = STANDARD
            .decode(encoded)
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
            key: *key,
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

/// Managed cipher for historical interaction readers and compatibility fixtures.
pub(crate) struct EvidenceCipher(RequestHeaderCipher);

impl EvidenceCipher {
    pub(crate) fn from_path(path: &Path) -> Result<Self> {
        Ok(Self(RequestHeaderCipher::from_environment_or_request_path(
            Some(path),
        )?))
    }

    #[cfg(test)]
    pub(crate) fn encrypt(&self, label: &str, bytes: &[u8]) -> Result<String> {
        self.0.encrypt(label, bytes)
    }

    pub(crate) fn decrypt(&self, label: &str, value: &str) -> Result<Vec<u8>> {
        self.0.decrypt(label, value)
    }
}

/// Engine-only key resolution shared with evidence integrity authentication.
pub(crate) fn managed_evidence_key(path: &Path) -> Result<[u8; AES_256_KEY_BYTES]> {
    Ok(RequestHeaderCipher::from_environment_or_request_path(Some(path))?.key)
}

pub(crate) fn encrypt_evidence(path: &Path, label: &str, bytes: &[u8]) -> Result<String> {
    RequestHeaderCipher::from_environment_or_request_path(Some(path))?.encrypt(label, bytes)
}
pub(crate) fn decrypt_evidence(path: &Path, label: &str, value: &str) -> Result<Vec<u8>> {
    RequestHeaderCipher::from_environment_or_request_path(Some(path))?.decrypt(label, value)
}

pub(crate) fn generate_encryption_key() -> Result<String> {
    let mut key = [0_u8; AES_256_KEY_BYTES];
    getrandom::fill(&mut key).map_err(|error| {
        anyhow::anyhow!("failed to generate request-header encryption key: {error}")
    })?;
    Ok(STANDARD.encode(key))
}

pub(crate) fn validate_encryption_key(encoded: &str) -> Result<()> {
    let _ = RequestHeaderCipher::from_encoded_key(encoded)?;
    ensure!(
        STANDARD.encode(STANDARD.decode(encoded)?) == encoded,
        "{ENCRYPTION_KEY_ENV} must use canonical Base64"
    );
    Ok(())
}

pub(crate) fn project_encryption_key_path(request_path: &Path) -> Option<PathBuf> {
    request_path.ancestors().find_map(|ancestor| {
        let is_local = ancestor.file_name().is_some_and(|name| name == "local")
            && ancestor
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == ".traffic-e2e");
        is_local.then(|| ancestor.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL))
    })
}

#[cfg(test)]
mod tests {
    use hyper::header::{AUTHORIZATION, HeaderValue};

    use super::*;

    const KEY: [u8; AES_256_KEY_BYTES] = [7; AES_256_KEY_BYTES];

    #[test]
    fn decrypts_dependency_headers_and_keeps_custom_encrypted_names_protected() {
        let key = match std::env::var(ENCRYPTION_KEY_ENV) {
            Ok(value) => STANDARD
                .decode(value)
                .unwrap()
                .try_into()
                .unwrap_or_else(|_| panic!("test requires an AES-256 key")),
            Err(_) => KEY,
        };
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path().join(".traffic-e2e/local");
        let key_path = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(key_path, STANDARD.encode(key)).unwrap();
        let cipher = RequestHeaderCipher::from_key(&key);
        let mut headers = HeaderSnapshot::from([
            (
                "authorization".into(),
                vec![
                    cipher
                        .encrypt("authorization", b"Bearer source-token")
                        .unwrap(),
                ],
            ),
            (
                "private-context".into(),
                vec![
                    cipher
                        .encrypt("private-context", b"secret-context")
                        .unwrap(),
                ],
            ),
            ("tenant-id".into(), vec!["tenant".into()]),
            ("private-redacted".into(), vec!["<redacted>".into()]),
        ]);
        let protected = decrypt_dependency_headers(
            &mut headers,
            &local.join("recordings/case/dependencies.jsonl"),
        )
        .unwrap();
        assert_eq!(headers["authorization"], ["Bearer source-token"]);
        assert_eq!(headers["private-context"], ["secret-context"]);
        assert_eq!(
            protected,
            BTreeSet::from([
                "authorization".into(),
                "private-context".into(),
                "private-redacted".into()
            ])
        );
        headers.insert(
            "private-context".into(),
            vec![
                cipher
                    .encrypt("private-context", b"secret-context")
                    .unwrap()
                    .replace("aes-256-gcm", "unsupported"),
            ],
        );
        assert!(
            decrypt_dependency_headers(
                &mut headers,
                &local.join("recordings/case/dependencies.jsonl")
            )
            .is_err()
        );
    }

    #[test]
    fn default_recording_preserves_authentication_headers_for_replay() {
        let config: crate::config::RecordingConfig = serde_yaml::from_str("{}").unwrap();
        let capture = RequestHeaderCapture::from_environment(
            &config.encrypt_request_headers,
            &config.redact_headers,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer test-token"),
        );
        headers.insert("cookie", HeaderValue::from_static("session=test-session"));
        headers.insert(
            "proxy-authorization",
            HeaderValue::from_static("Basic test"),
        );

        let request = serde_json::json!({
            "method": "GET",
            "uri": "/resource",
            "headers": capture.capture(&headers).unwrap(),
        });
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("request.json");
        std::fs::write(&path, serde_json::to_vec(&request).unwrap()).unwrap();
        let replay: Value = serde_json::from_slice(&load_request_file(&path).unwrap()).unwrap();

        for (name, value) in &headers {
            assert_eq!(replay["headers"][name.as_str()][0], value.to_str().unwrap());
        }
    }

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
    fn generates_a_strict_project_key_and_resolves_its_fixed_location() {
        let encoded = generate_encryption_key().unwrap();
        validate_encryption_key(&encoded).unwrap();
        assert_eq!(STANDARD.decode(encoded).unwrap().len(), AES_256_KEY_BYTES);

        let request = Path::new(
            "/target/.traffic-e2e/local/artifacts/recordings/20260903132752/apis/get/case/request.json",
        );
        assert_eq!(
            project_encryption_key_path(request).unwrap(),
            PathBuf::from("/target/.traffic-e2e/local/secrets/traffic-e2e-enc.sec")
        );
        assert!(project_encryption_key_path(Path::new("/external/request.json")).is_none());
    }

    #[test]
    fn uses_a_fresh_nonce_for_each_value() {
        let cipher = RequestHeaderCipher::from_key(&KEY);

        let first = cipher.encrypt("authorization", b"same").unwrap();
        let second = cipher.encrypt("authorization", b"same").unwrap();

        assert_ne!(first, second);
    }
}
