//! Attribute a direct successful write-to-COMMIT handoff, without claiming a transaction prefix.
use super::*;

pub(super) fn prove(
    group: &[&Exchange],
    files: &[EvidenceFile],
    owners: &BTreeMap<String, &BackgroundDependencyRuleConfig>,
) -> Option<OriginWitness> {
    let [write, commit] = group else {
        return None;
    };
    let origin = write.origin.as_ref()?;
    let BackgroundDependencyRuleConfig::Mysql { selector, .. } = owners.get(&origin.rule)? else {
        return None;
    };
    if !selector
        .sql
        .split_whitespace()
        .next()?
        .eq_ignore_ascii_case("UPDATE")
        || commit.command != "commit"
        || !write.complete
        || !commit.complete
        || write.before? & 0x2009 != 1
        || write.after? & 0x2009 != 1
        || commit.before? & 0x2009 != 1
        || commit.after? & 0x2009 != 0
        || !independent(write, origin, files, owners)
        || !independent(commit, origin, files, owners)
    {
        return None;
    }
    Some(origin.clone())
}
