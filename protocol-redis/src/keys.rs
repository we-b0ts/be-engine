//! Byte-preserving Redis key selectors.
pub fn matches_redis_key(key: &[u8], prefix: &[u8], suffix: &[u8]) -> bool {
    key.starts_with(prefix) && key.ends_with(suffix)
}

pub fn matches_redis_numeric_key_pattern(key: &[u8], prefix: &[u8], suffix: &[u8]) -> bool {
    let Some(middle) = key
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
    else {
        return false;
    };
    !middle.is_empty() && middle.iter().all(u8::is_ascii_digit)
}
