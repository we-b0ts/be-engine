use std::path::{Path, PathBuf};

pub(crate) const REPOSITORY_RELATIVE_ROOT: &str = ".traffic-e2e/.ai-forbidden";
pub(crate) const TRAFFIC_E2E_RELATIVE_ROOT: &str = ".ai-forbidden";
pub(crate) const GIT_PATHSPEC: &str = ":(exclude).traffic-e2e/.ai-forbidden/**";

pub(crate) fn root(target_root: &Path) -> PathBuf {
    target_root.join(REPOSITORY_RELATIVE_ROOT)
}
