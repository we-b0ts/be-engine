//! Exact identity of an EVAL script and its ordered KEYS envelope.
use sha2::{Digest, Sha256};

/// Read only the arguments required to identify the script invocation. Callers
/// can supply raw arguments or decode selected arguments from recorded evidence.
pub fn matches_eval<B: AsRef<[u8]>>(
    argument_count: usize,
    argument: impl Fn(usize) -> Option<B>,
    sha256: &str,
    keys: &[impl AsRef<str>],
) -> bool {
    let Some(count) = argument(1) else {
        return false;
    };
    let Ok(slots) = super::key_slots::script_key_slots(count.as_ref(), argument_count) else {
        return false;
    };
    slots.len() == keys.len()
        && slots.zip(keys).all(|(slot, expected)| {
            argument(slot).is_some_and(|key| key.as_ref() == expected.as_ref().as_bytes())
        })
        && argument(0).is_some_and(|script| format!("{:x}", Sha256::digest(script)) == sha256)
}
