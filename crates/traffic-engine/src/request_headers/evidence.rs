//! Select configured HTTP header values without changing the surrounding bytes.
use super::*;
use serde_json::value::RawValue;
use std::ops::Range;

#[derive(Debug, Default)]
pub(crate) struct HeaderPolicy {
    names: HashSet<String>,
}

pub(crate) struct HeaderValueRange {
    pub(crate) name: String,
    pub(crate) range: Range<usize>,
}

impl HeaderPolicy {
    pub(crate) fn load(context: &Path) -> Result<Self> {
        let Some(key_path) = project_encryption_key_path(context) else {
            return Ok(Self::default());
        };
        let config = key_path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .context("managed evidence context has no project directory")?
            .join("project.yaml");
        let names = if config.try_exists()? {
            crate::AppConfig::encrypted_request_header_names(&config)?
        } else {
            Vec::new()
        };
        Ok(Self {
            names: normalize_names(&names),
        })
    }

    pub(crate) fn ranges(&self, bytes: &[u8]) -> Result<Vec<HeaderValueRange>> {
        if self.names.is_empty() {
            return Ok(Vec::new());
        }
        let Ok(object) = serde_json::from_slice::<BTreeMap<&str, &RawValue>>(bytes) else {
            return Ok(Vec::new());
        };
        let http = object
            .get("protocol")
            .is_some_and(|value| value.get() == "\"http\"")
            || object.contains_key("contract");
        if !http {
            return Ok(Vec::new());
        }
        let mut ranges = Vec::new();
        for field in ["request_headers", "headers"] {
            let Some(headers) = object.get(field) else {
                continue;
            };
            let headers: BTreeMap<&str, &RawValue> = serde_json::from_str(headers.get())?;
            for (name, values) in headers {
                if !self.names.contains(&name.to_ascii_lowercase()) {
                    continue;
                }
                let values: Vec<&RawValue> = serde_json::from_str(values.get())?;
                for value in values {
                    let text: String = serde_json::from_str(value.get())?;
                    if text.starts_with("traffic-e2e:enc:") || text == "<redacted>" {
                        continue;
                    }
                    let start = value.get().as_ptr() as usize - bytes.as_ptr() as usize;
                    ranges.push(HeaderValueRange {
                        name: name.to_ascii_lowercase(),
                        range: start..start + value.get().len(),
                    });
                }
            }
        }
        ranges.sort_by_key(|value| value.range.start);
        Ok(ranges)
    }
}
