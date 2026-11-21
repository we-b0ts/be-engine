use std::path::{Path, PathBuf};

pub const REPOSITORY_RELATIVE_ROOT: &str = ".traffic-e2e/local/runtime";
pub const PROJECT_RELATIVE_ROOT: &str = "local/runtime";
pub const LOCAL_GIT_PATHSPEC: &str = ":(exclude).traffic-e2e/local/**";

pub fn root(target_root: &Path) -> PathBuf {
    target_root.join(REPOSITORY_RELATIVE_ROOT)
}
