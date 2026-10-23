//! Bounded proof summaries and explicit Source reference lists.
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer};

use super::Proof;

#[cfg(test)]
mod tests;

pub const MAX_PROOF_FACT_BYTES: usize = 200;
pub const MAX_PROOF_SOURCE_REFERENCES: usize = 3;

pub(crate) fn references(source: &str) -> Result<Vec<&str>> {
    let source = source.rsplit_once(" @ ").map_or(source, |(text, _)| text);
    let references = source.split(';').map(str::trim).collect::<Vec<_>>();
    ensure!(
        references.len() <= MAX_PROOF_SOURCE_REFERENCES
            && references
                .iter()
                .all(|reference| !reference.is_empty() && !reference.contains(" @ ")),
        "proof.source requires 1..={MAX_PROOF_SOURCE_REFERENCES} file references"
    );
    Ok(references)
}

pub(crate) fn deserialize_source<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Source {
        One(String),
        Many(Vec<String>),
    }
    let source = match Source::deserialize(deserializer)? {
        Source::One(source) => source,
        Source::Many(sources) => {
            if sources.is_empty()
                || sources.len() > MAX_PROOF_SOURCE_REFERENCES
                || sources.iter().any(|source| {
                    source.contains(';') || source.contains(" @ ") || source.trim().is_empty()
                })
            {
                return Err(serde::de::Error::custom(format!(
                    "proof.source requires 1..={MAX_PROOF_SOURCE_REFERENCES} separate file references"
                )));
            }
            sources.join("; ")
        }
    };
    Ok(source)
}

impl Proof {
    pub(crate) fn merged_source(&self, other: &Self) -> Result<String> {
        let revision = |source: &str| {
            source
                .rsplit_once(" @ ")
                .map(|(_, revision)| revision.to_owned())
        };
        let left = revision(&self.source);
        let right = revision(&other.source);
        ensure!(
            left.is_none() || right.is_none() || left == right,
            "cannot merge proofs from different Source revisions"
        );
        let mut files = Vec::new();
        for file in references(&self.source)?
            .into_iter()
            .chain(references(&other.source)?)
        {
            if !files.contains(&file) {
                files.push(file);
            }
        }
        ensure!(
            files.len() <= MAX_PROOF_SOURCE_REFERENCES,
            "combined proof.source exceeds {MAX_PROOF_SOURCE_REFERENCES} file references; provide a concise complete proof"
        );
        let source = files.join("; ");
        Ok(match left.or(right) {
            Some(revision) => format!("{source} @ {revision}"),
            None => source,
        })
    }

    pub(crate) fn validate(&self, source_optional: bool) -> Result<()> {
        ensure!(
            !self.fact.trim().is_empty()
                && self.fact.len() <= MAX_PROOF_FACT_BYTES
                && !self.fact.contains(['\r', '\n', '\0']),
            "proof.fact must be a nonempty single line of at most {MAX_PROOF_FACT_BYTES} UTF-8 bytes"
        );
        if source_optional && self.source.is_empty() {
            return Ok(());
        }
        ensure!(
            !self.source.trim().is_empty()
                && self.source.len() <= 2048
                && !self.source.contains(['\r', '\n', '\0']),
            "proof.source must be a nonempty single line of at most 2048 UTF-8 bytes"
        );
        references(&self.source)?;
        Ok(())
    }
}
