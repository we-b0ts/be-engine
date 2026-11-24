//! Match validated JSON Pointer patterns against one document.
use std::{borrow::Cow, fmt::Write as _, ops::Range};

use anyhow::Result;
use serde_json::Value;

/// The decoded keys and array coordinates of one authored selector.
#[derive(Debug)]
pub struct CompiledSelector {
    pattern: Box<str>,
    segments: Box<[CompiledSegment]>,
    wildcard: bool,
}

#[derive(Debug)]
struct CompiledSegment {
    encoded: Range<usize>,
    unescaped: Option<Box<str>>,
    index: Option<usize>,
}

struct Segment<'a> {
    encoded: &'a str,
    key: Cow<'a, str>,
    index: Option<usize>,
}

impl CompiledSelector {
    pub fn new(pattern: &str) -> Result<Self> {
        crate::path::validate_pointer(pattern, true)?;
        let mut start = 1;
        let mut wildcard = false;
        let segments = segments(pattern)
            .map(|encoded| {
                let end = start + encoded.len();
                wildcard |= encoded == "*";
                let segment = CompiledSegment {
                    encoded: start..end,
                    unescaped: encoded.contains('~').then(|| unescape(encoded).into()),
                    index: array_index(encoded),
                };
                start = end + 1;
                segment
            })
            .collect();
        Ok(Self {
            pattern: pattern.into(),
            segments,
            wildcard,
        })
    }

    pub fn visit<'a>(
        &self,
        source: &'a Value,
        visitor: impl FnMut(&str, &'a Value) -> Result<()>,
    ) -> Result<()> {
        let parts = self.segments.iter().map(|segment| {
            let encoded = &self.pattern[segment.encoded.clone()];
            Segment {
                encoded,
                key: Cow::Borrowed(segment.unescaped.as_deref().unwrap_or(encoded)),
                index: segment.index,
            }
        });
        visit(&self.pattern, parts, self.wildcard, source, visitor)
    }
}

pub fn select(pattern: &str, value: &Value) -> Result<Vec<String>> {
    let mut selected = Vec::new();
    visit_uncompiled(pattern, value, |pointer, _| {
        selected.push(pointer.to_owned());
        Ok(())
    })?;
    Ok(selected)
}

pub fn visit_uncompiled<'a>(
    pattern: &str,
    source: &'a Value,
    visitor: impl FnMut(&str, &'a Value) -> Result<()>,
) -> Result<()> {
    crate::path::validate_pointer(pattern, true)?;
    let parts = segments(pattern).map(|encoded| Segment {
        encoded,
        key: if encoded.contains('~') {
            Cow::Owned(unescape(encoded))
        } else {
            Cow::Borrowed(encoded)
        },
        index: array_index(encoded),
    });
    visit(pattern, parts, pattern.contains('*'), source, visitor)
}

fn segments(pattern: &str) -> impl Iterator<Item = &str> + Clone {
    pattern.split('/').skip(1)
}

fn unescape(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

fn array_index(segment: &str) -> Option<usize> {
    if segment.starts_with('+') || (segment.starts_with('0') && segment != "0") {
        return None;
    }
    segment.parse().ok()
}

impl Segment<'_> {
    fn child<'a>(&self, value: &'a Value) -> Option<&'a Value> {
        match value {
            Value::Object(fields) => fields.get(self.key.as_ref()),
            Value::Array(values) => values.get(self.index?),
            _ => None,
        }
    }
}

fn visit<'a, 'p>(
    pattern: &str,
    mut parts: impl Iterator<Item = Segment<'p>> + Clone,
    wildcard: bool,
    value: &'a Value,
    mut visitor: impl FnMut(&str, &'a Value) -> Result<()>,
) -> Result<()> {
    if wildcard {
        walk(parts, value, &mut String::new(), &mut visitor)?;
    } else if let Some(matched) = parts.try_fold(value, |value, part| part.child(value)) {
        visitor(pattern, matched)?;
    }
    Ok(())
}

fn walk<'a, 'p>(
    mut parts: impl Iterator<Item = Segment<'p>> + Clone,
    value: &'a Value,
    path: &mut String,
    visitor: &mut impl FnMut(&str, &'a Value) -> Result<()>,
) -> Result<()> {
    let Some(part) = parts.next() else {
        return visitor(path, value);
    };
    let prefix_length = path.len();
    if part.encoded == "*" {
        if let Some(values) = value.as_array() {
            for (index, value) in values.iter().enumerate() {
                write!(path, "/{index}").expect("writing a String is infallible");
                walk(parts.clone(), value, path, visitor)?;
                path.truncate(prefix_length);
            }
        }
    } else if let Some(value) = part.child(value) {
        path.push('/');
        path.push_str(part.encoded);
        walk(parts, value, path, visitor)?;
        path.truncate(prefix_length);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compiled_selectors_share_exact_and_array_wildcard_semantics() {
        let source = json!({"": {"a~/中": [[7, 8], [9]], "~1": null, "x*y": 4}});
        for pattern in ["", "/", "//a~0~1中/*/0", "//a~0~1中/01", "//~01", "//x*y"] {
            let selector = CompiledSelector::new(pattern).unwrap();
            let mut matches = Vec::new();
            selector
                .visit(&source, |pointer, value| {
                    assert_eq!(source.pointer(pointer), Some(value));
                    matches.push(pointer.to_owned());
                    Ok(())
                })
                .unwrap();
            assert_eq!(matches, select(pattern, &source).unwrap(), "{pattern}");
        }
        assert!(CompiledSelector::new("/missing/~2").is_err());
    }
}
