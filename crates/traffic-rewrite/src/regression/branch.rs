//! Daily, monotonic branch allocation for purpose entry. No refs are mutated here.
use crate::source_diff;
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn next(root: &Path, record: bool) -> Result<String> {
    let date = chrono::Local::now().format("%Y%m%d").to_string();
    let refs = source_diff::git_text(
        root,
        &[
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads/",
            "refs/remotes/",
        ],
    )?;
    allocate(&refs, if record { "record" } else { "replay" }, &date)
}

fn allocate(refs: &str, purpose: &str, date: &str) -> Result<String> {
    let prefix = format!("{purpose}/{date}-");
    let local = format!("refs/heads/{prefix}");
    let remote_suffix = format!("/{prefix}");
    let max = refs
        .lines()
        .filter_map(|name| {
            name.strip_prefix(&local)
                .or_else(|| {
                    name.strip_prefix("refs/remotes/")?
                        .rsplit_once(&remote_suffix)
                        .map(|(_, suffix)| suffix)
                })
                .and_then(|suffix| suffix.parse::<u64>().ok())
        })
        .max()
        .unwrap_or(0);
    let seq = max
        .checked_add(1)
        .context("purpose branch sequence exhausted")?;
    Ok(format!("{prefix}{seq}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sequence_uses_max_existing_local_and_remote_for_the_same_day_and_purpose() {
        let refs = "refs/heads/replay/20260912-1\nrefs/heads/replay/20260912-3\nrefs/remotes/origin/replay/20260912-5\nrefs/heads/record/20260912-20\nrefs/heads/replay/20260911-99\nrefs/heads/replay/20260912-invalid\n";
        assert_eq!(
            allocate(refs, "replay", "20260912").unwrap(),
            "replay/20260912-6"
        );
        assert_eq!(
            allocate(refs, "record", "20260912").unwrap(),
            "record/20260912-21"
        );
        assert_eq!(
            allocate(refs, "replay", "20260913").unwrap(),
            "replay/20260913-1"
        );
    }
}
