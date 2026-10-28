//! Partial-attempt eligibility preserves owners and requires ordinary complete preflight.
use crate::policy::CompiledPolicy;

pub(super) fn removes_only_read_back(before: &CompiledPolicy, after: &CompiledPolicy) -> bool {
    let removed = before
        .native
        .iter()
        .filter(|old| !after.native.contains(old))
        .collect::<Vec<_>>();
    if removed.is_empty()
        || !removed
            .iter()
            .all(|old| crate::policy::native::is_key_only_read_back(&old.rule))
    {
        return false;
    }
    let mut expected = before.clone();
    expected.native.retain(|old| after.native.contains(old));
    // Digests identify the resulting policy; compare every compiled permission,
    // owner, format and signature independently of these derived digests.
    expected.fingerprints = after.fingerprints.clone();
    expected == *after
}

/// Existing identity semantics may use another explicit representation after
/// Source-wide validation and independent Target preflight. This is not an
/// ownership/capture change and never certifies the unfinished Replay.
pub(super) fn allows_partial(before: &CompiledPolicy, after: &CompiledPolicy) -> bool {
    if removes_only_read_back(before, after) {
        return true;
    }
    let (Some(old), Some(new)) = (&before.global_json, &after.global_json) else {
        return false;
    };
    if !old.fields.keys().eq(new.fields.keys()) || old.fields == new.fields {
        return false;
    }
    for (pointer, old) in &old.fields {
        let new = &new.fields[pointer];
        if old == new {
            continue;
        }
        let (
            crate::policy::GlobalField::Identity { formats: old },
            crate::policy::GlobalField::Identity { formats: new },
        ) = (old, new)
        else {
            return false;
        };
        let prefixes = |formats: &[crate::policy::GlobalIdentityFormat]| {
            formats
                .iter()
                .map(|format| format.prefix.clone())
                .collect::<std::collections::BTreeSet<_>>()
        };
        if prefixes(old) != prefixes(new) {
            return false;
        }
    }
    let mut expected = before.clone();
    let json = expected.global_json.as_mut().unwrap();
    json.fields = new.fields.clone();
    json.fingerprint = new.fingerprint.clone();
    expected.fingerprints = after.fingerprints.clone();
    expected == *after
}
