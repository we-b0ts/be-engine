//! Logical selectors shared by codec and policy implementations.
use std::borrow::Cow;

use anyhow::{Result, ensure};

pub fn validate(pointer: &str, wildcard: bool) -> Result<()> {
    ensure!(
        pointer.len() <= 1024 && (pointer.is_empty() || pointer.starts_with('/')),
        "field selector requires a bounded pointer"
    );
    ensure!(
        !pointer.contains(['\r', '\n', '\0']),
        "field selector contains control characters"
    );
    for segment in pointer.split('/').skip(1) {
        ensure!(
            wildcard || segment != "*",
            "selector requires an exact path"
        );
        let mut characters = segment.chars();
        while let Some(character) = characters.next() {
            if character == '~' {
                ensure!(
                    matches!(characters.next(), Some('0' | '1')),
                    "invalid field selector escape"
                );
            }
        }
    }
    Ok(())
}

pub fn escape(segment: &str) -> String {
    let mut escaped = String::with_capacity(segment.len());
    push_escaped(&mut escaped, segment);
    escaped
}

/// Append a literal key to a JSON Pointer without allocating a separate segment.
pub fn push_segment(pointer: &mut String, segment: &str) {
    pointer.push('/');
    push_escaped(pointer, segment);
}

fn push_escaped(output: &mut String, segment: &str) {
    let mut start = 0;
    for (index, character) in segment.match_indices(['~', '/']) {
        output.push_str(&segment[start..index]);
        output.push_str(if character == "~" { "~0" } else { "~1" });
        start = index + 1;
    }
    output.push_str(&segment[start..]);
}

pub(crate) fn unescape(segment: &str) -> Cow<'_, str> {
    if segment.contains('~') {
        Cow::Owned(segment.replace("~1", "/").replace("~0", "~"))
    } else {
        Cow::Borrowed(segment)
    }
}

pub fn matches(pattern: &str, pointer: &str) -> bool {
    pattern.split('/').count() == pointer.split('/').count()
        && pattern.split('/').zip(pointer.split('/')).all(|(a, b)| {
            a == b || a == "*" && b.parse::<usize>().is_ok() && (b == "0" || !b.starts_with('0'))
        })
}

pub fn overlaps(left: &str, right: &str) -> bool {
    left.split('/')
        .skip(1)
        .zip(right.split('/').skip(1))
        .all(|(left, right)| left == right || left == "*" || right == "*")
}
