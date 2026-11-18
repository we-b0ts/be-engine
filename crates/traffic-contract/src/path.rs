//! Bounded logical field selectors.
use anyhow::{Result, ensure};

pub fn validate_pointer(pointer: &str, wildcard: bool) -> Result<()> {
    ensure!(
        pointer.len() <= 1024 && (pointer.is_empty() || pointer.starts_with('/')),
        "field selector requires a bounded JSON Pointer"
    );
    ensure!(
        !pointer.contains(['\r', '\n', '\0']),
        "field selector contains control characters"
    );
    for segment in pointer.split('/').skip(1) {
        ensure!(
            wildcard || segment != "*",
            "Source predicates require exact JSON Pointers"
        );
        let mut chars = segment.chars();
        while let Some(character) = chars.next() {
            if character == '~' {
                ensure!(
                    matches!(chars.next(), Some('0' | '1')),
                    "invalid JSON Pointer escape"
                );
            }
        }
    }
    Ok(())
}
