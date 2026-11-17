use std::fmt::Write as _;
use std::path::Path;

pub(crate) fn whole_file_diff(path: &Path, original: &str, updated: &str) -> String {
    let old_count = original.lines().count();
    let new_count = updated.lines().count();
    let mut diff = format!(
        "--- {0}\n+++ {0}\n@@ -1,{old_count} +1,{new_count} @@\n",
        path.display()
    );
    for line in original.lines() {
        let _ = writeln!(diff, "-{line}");
    }
    for line in updated.lines() {
        let _ = writeln!(diff, "+{line}");
    }
    diff
}
