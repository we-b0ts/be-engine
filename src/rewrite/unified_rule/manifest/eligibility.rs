//! Partial execution can revoke a key-local read-back permission, never grant one.
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
