use std::path::{Path, PathBuf};

pub fn group_dir(run: &Path, category: &str, readable_name: &str) -> PathBuf {
    let prefix = format!("{readable_name}-");
    let groups = std::fs::read_dir(run.join(category))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(&prefix)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        groups.len(),
        1,
        "expected one recording group for {category}/{readable_name}"
    );
    groups[0].clone()
}
