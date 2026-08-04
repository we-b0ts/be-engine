use std::path::{Path, PathBuf};

pub(crate) const REPOSITORY_RELATIVE_ROOT: &str = ".traffic-e2e/local/ai-forbidden";
pub(crate) const TRAFFIC_E2E_RELATIVE_ROOT: &str = "local/ai-forbidden";
pub(crate) const LOCAL_GIT_PATHSPEC: &str = ":(exclude).traffic-e2e/local/**";

pub(crate) fn root(target_root: &Path) -> PathBuf {
    target_root.join(REPOSITORY_RELATIVE_ROOT)
}
