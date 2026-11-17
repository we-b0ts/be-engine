//! Plaintext traffic bytes with encryption only at configured HTTP header values.
use super::*;
use crate::request_headers::evidence::HeaderValueRange;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum StoredPayload {
    Plaintext(Plaintext),
    Headers {
        parts: Vec<Part>,
    },
    Encrypted {
        #[serde(alias = "encrypted_target")]
        encrypted: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plaintext {
    encoding: Encoding,
    data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Encoding {
    Utf8,
    Base64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Part {
    Plaintext { value: Plaintext },
    Header { name: String, encrypted: String },
}

impl Plaintext {
    fn capture(bytes: &[u8]) -> Self {
        if let Ok(text) = std::str::from_utf8(bytes)
            // Keep JSON escaping within the same bounded chunk budget as Base64.
            && serde_json::to_string(text).is_ok_and(|value|
                value.len() <= bytes.len().div_ceil(3) * 4 + 2)
        {
            return Self {
                encoding: Encoding::Utf8,
                data: text.into(),
            };
        }
        Self {
            encoding: Encoding::Base64,
            data: STANDARD.encode(bytes),
        }
    }

    fn read(&self) -> Result<Vec<u8>> {
        match self.encoding {
            Encoding::Utf8 => Ok(self.data.as_bytes().to_vec()),
            Encoding::Base64 => Ok(STANDARD.decode(&self.data)?),
        }
    }
}

impl StoredPayload {
    pub(crate) fn capture(
        bytes: &[u8],
        offset: usize,
        ranges: &[HeaderValueRange],
        context: &Path,
    ) -> Result<Self> {
        let end = offset + bytes.len();
        let mut cursor = 0;
        let mut parts = Vec::new();
        for header in ranges {
            let start = header.range.start.max(offset);
            let stop = header.range.end.min(end);
            if start >= stop {
                continue;
            }
            let start = start - offset;
            let stop = stop - offset;
            if cursor < start {
                parts.push(Part::Plaintext {
                    value: Plaintext::capture(&bytes[cursor..start]),
                });
            }
            parts.push(Part::Header {
                name: header.name.clone(),
                encrypted: crate::request_headers::encrypt_evidence(
                    context,
                    &header_label(&header.name),
                    &bytes[start..stop],
                )?,
            });
            cursor = stop;
        }
        if parts.is_empty() {
            return Ok(Self::Plaintext(Plaintext::capture(bytes)));
        }
        if cursor < bytes.len() {
            parts.push(Part::Plaintext {
                value: Plaintext::capture(&bytes[cursor..]),
            });
        }
        Ok(Self::Headers { parts })
    }

    pub(crate) fn read(&self, context: &Path, legacy_label: &str) -> Result<Vec<u8>> {
        match self {
            Self::Plaintext(value) => value.read(),
            Self::Encrypted { encrypted } => {
                crate::request_headers::decrypt_evidence(context, legacy_label, encrypted)
            }
            Self::Headers { parts } => {
                let mut bytes = Vec::new();
                for part in parts {
                    bytes.extend(match part {
                        Part::Plaintext { value } => value.read()?,
                        Part::Header { name, encrypted } => {
                            crate::request_headers::decrypt_evidence(
                                context,
                                &header_label(name),
                                encrypted,
                            )?
                        }
                    });
                }
                Ok(bytes)
            }
        }
    }
}

fn header_label(name: &str) -> String {
    format!("evidence-request-header/v1/{name}")
}

#[cfg(test)]
mod tests;
