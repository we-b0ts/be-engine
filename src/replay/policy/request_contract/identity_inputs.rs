//! Fixed API inputs constrain eligible resource identities without granting permission.
//! One lazy index contains exact input scalars, never substrings or payload copies.
use super::*;
use sha2::{Digest, Sha256};

const MAX_INPUT_POSITIONS: usize = 16384;
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_IDENTITY_TEXT: usize = 512;

pub(super) fn capture_error(request: &Value, json: Option<&Value>) -> Option<&'static str> {
    let body = request.get("body")?;
    if body["truncated"] == true
        || body
            .get("decode_error")
            .is_some_and(|error| !error.is_null())
    {
        return Some("API input capture is incomplete");
    }
    if json.is_none() && body["data"].as_str().is_some_and(|data| !data.is_empty()) {
        return Some("nonempty API input requires complete JSON for identity anchoring");
    }
    None
}

#[derive(Default)]
pub(super) struct InputIndex {
    values: BTreeSet<[u8; 32]>,
    failure: Option<String>,
}

impl InputIndex {
    fn build(uri: &str, body: Option<&Value>) -> Self {
        let mut index = Self::default();
        if let Err(error) = index.collect(uri, body) {
            index.values.clear();
            index.failure = Some(error.to_string());
        }
        index
    }

    fn collect(&mut self, uri: &str, body: Option<&Value>) -> Result<()> {
        let mut budget = Budget {
            positions: 0,
            bytes: uri.len(),
        };
        ensure!(
            budget.bytes <= MAX_INPUT_BYTES,
            "identity input byte bound exceeded"
        );
        let parsed = uri.parse::<hyper::Uri>().ok();
        let path = parsed
            .as_ref()
            .map(hyper::Uri::path)
            .unwrap_or_else(|| uri.split('?').next().unwrap_or_default());
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            let decoded = decode_path_segment(segment)?;
            budget.visit(decoded.len())?;
            self.insert(&decoded);
        }
        let query = parsed
            .as_ref()
            .and_then(hyper::Uri::query)
            .or_else(|| uri.split_once('?').map(|(_, query)| query));
        if let Some(query) = query {
            for (_, value) in ::url::form_urlencoded::parse(query.as_bytes()) {
                budget.visit(value.len())?;
                self.insert(&value);
            }
        }
        if let Some(body) = body {
            self.collect_json(body, &mut budget, 0)?;
        }
        Ok(())
    }

    fn collect_json(&mut self, value: &Value, budget: &mut Budget, depth: usize) -> Result<()> {
        ensure!(depth <= 128, "identity input nesting bound exceeded");
        budget.visit(1)?;
        match value {
            Value::String(value) => {
                budget.add_bytes(value.len())?;
                self.insert(value);
            }
            Value::Number(value) => {
                if let Some(value) = value.as_u64() {
                    self.insert(&value.to_string());
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.collect_json(value, budget, depth + 1)?;
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    budget.add_bytes(key.len())?;
                    self.collect_json(value, budget, depth + 1)?;
                }
            }
            Value::Bool(_) | Value::Null => {}
        }
        Ok(())
    }

    fn insert(&mut self, value: &str) {
        // A declared prefix plus a canonical identity token cannot exceed 512
        // bytes. Longer business text cannot be an exact identity occurrence.
        if !value.is_empty() && value.len() <= MAX_IDENTITY_TEXT {
            self.values.insert(Sha256::digest(value.as_bytes()).into());
        }
    }

    fn contains(&self, value: &str) -> bool {
        self.values
            .contains(&<[u8; 32]>::from(Sha256::digest(value.as_bytes())))
    }
}

struct Budget {
    positions: usize,
    bytes: usize,
}

impl Budget {
    fn visit(&mut self, bytes: usize) -> Result<()> {
        self.positions += 1;
        ensure!(
            self.positions <= MAX_INPUT_POSITIONS,
            "identity input position bound exceeded"
        );
        self.add_bytes(bytes)
    }

    fn add_bytes(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("identity input byte bound exceeded")?;
        ensure!(
            self.bytes <= MAX_INPUT_BYTES,
            "identity input byte bound exceeded"
        );
        Ok(())
    }
}

fn decode_path_segment(segment: &str) -> Result<String> {
    let mut decoded = Vec::with_capacity(segment.len());
    let mut remaining = segment.as_bytes();
    while let Some((&first, rest)) = remaining.split_first() {
        if first == b'%' {
            let escape = rest
                .get(..2)
                .context("invalid identity input path escape")?;
            let escape =
                std::str::from_utf8(escape).context("invalid identity input path escape")?;
            decoded.push(
                u8::from_str_radix(escape, 16).context("invalid identity input path escape")?,
            );
            remaining = &rest[2..];
        } else {
            decoded.push(first);
            remaining = rest;
        }
    }
    String::from_utf8(decoded).context("identity input path is not UTF-8")
}

impl RequestContracts {
    fn identity_input_index(&self, case: &str) -> Arc<InputIndex> {
        let snapshot = {
            let state = self.state.lock().expect("request contracts");
            if let Some(index) = state.identity_inputs.get(case) {
                return Arc::clone(index);
            }
            state.cases.get(case).map(|anchor| {
                (
                    anchor.source_uri.clone(),
                    anchor.source_body.clone(),
                    anchor.source_input_error,
                )
            })
        };
        // Parsing, bounded traversal and hashing stay outside the shared mutex.
        let index = Arc::new(
            snapshot.map_or_else(InputIndex::default, |(uri, body, error)| {
                error.map_or_else(
                    || InputIndex::build(&uri, body.as_ref()),
                    |error| InputIndex {
                        failure: Some(error.into()),
                        ..InputIndex::default()
                    },
                )
            }),
        );
        Arc::clone(
            self.state
                .lock()
                .expect("request contracts")
                .identity_inputs
                .entry(case.into())
                .or_insert(index),
        )
    }

    pub(super) fn validate_identity_input_anchors(
        &self,
        case: &str,
        pairs: &[crate::value_contract::identities::IdentityPair],
    ) -> Result<()> {
        if pairs.iter().all(|pair| pair.source == pair.target) {
            return Ok(());
        }
        let index = self.identity_input_index(case);
        ensure!(
            index.failure.is_none(),
            "fixed identity input index unavailable: {}",
            index.failure.as_deref().unwrap_or_default()
        );
        for pair in pairs.iter().filter(|pair| pair.source != pair.target) {
            let fixed = self.identity_prefixes.get(&pair.domain).map_or_else(
                || index.contains(&pair.source),
                |prefixes| {
                    prefixes.iter().any(|prefix| {
                        if prefix.is_empty() {
                            index.contains(&pair.source)
                        } else {
                            index.contains(&format!("{prefix}{}", pair.source))
                        }
                    })
                },
            );
            ensure!(
                !fixed,
                "identity supplied by the immutable API request must remain exact"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
