//! Explicit key slots and declared identity references, independent of project names.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum KeyContract {
    TimeWindow {
        window_seconds: u32,
        #[serde(default = "colon")]
        separator: char,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        segment_index: Option<usize>,
    },
    Capture {
        template: String,
        format: KeyFormat,
    },
    Reference {
        template: String,
        #[serde(default)]
        transform: Transform,
    },
}
fn colon() -> char {
    ':'
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum KeyFormat {
    Hex { bytes: usize },
    Base64url { bytes: usize },
    UuidV4,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Transform {
    #[default]
    Identity,
    Sha256,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityReference {
    pub template: String,
    #[serde(default)]
    pub transform: Transform,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityField {
    pub identity: IdentityReference,
}

pub(super) fn affixes(template: &str) -> Result<(&str, &str)> {
    ensure!(
        template.len() <= 1024 && template.matches("{value}").count() == 1,
        "identity template requires one bounded {{value}} slot"
    );
    let (prefix, suffix) = template.split_once("{value}").expect("validated slot");
    ensure!(
        !prefix.contains(['{', '}', '\r', '\n']) && !suffix.contains(['{', '}', '\r', '\n']),
        "identity template contains an undeclared slot"
    );
    Ok((prefix, suffix))
}
impl IdentityReference {
    pub(crate) fn validate(&self) -> Result<()> {
        affixes(&self.template)?;
        Ok(())
    }
}
impl KeyContract {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::TimeWindow {
                window_seconds,
                separator,
                segment_index,
            } => {
                ensure!(
                    (1..=31_536_000).contains(window_seconds)
                        && separator.is_ascii_punctuation()
                        && !matches!(separator, '{' | '}' | '\\')
                        && segment_index.is_none_or(|i| i < 64),
                    "key time window requires a bounded positive period and delimiter/segment"
                );
            }
            Self::Capture {
                template, format, ..
            } => {
                let (prefix, suffix) = affixes(template)?;
                ensure!(
                    !prefix.is_empty() || !suffix.is_empty(),
                    "key capture requires fixed affixes"
                );
                match format {
                    KeyFormat::Hex { bytes } | KeyFormat::Base64url { bytes } => ensure!(
                        (1..=256).contains(bytes),
                        "key identity length must be 1..256 bytes"
                    ),
                    KeyFormat::UuidV4 => (),
                }
            }
            Self::Reference {
                template,
                transform,
            } => IdentityReference {
                template: template.clone(),
                transform: *transform,
            }
            .validate()?,
        }
        Ok(())
    }
}
