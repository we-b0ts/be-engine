use std::path::Path;

use super::TargetQualityGateConfig;

pub(super) fn inferred_target_quality_gates(
    target_root: &Path,
    managed_paths: &[std::path::PathBuf],
) -> Vec<TargetQualityGateConfig> {
    std::iter::once(std::path::PathBuf::new())
        .chain(managed_paths.iter().cloned())
        .enumerate()
        .filter(|(_, path)| target_root.join(path).join("Cargo.toml").is_file())
        .flat_map(|(index, path)| {
            let manifest = path.join("Cargo.toml");
            if index == 0 {
                rust_quality_gates(None, None)
            } else {
                rust_quality_gates(Some(index), Some(&manifest))
            }
        })
        .collect()
}

fn rust_quality_gates(
    managed_index: Option<usize>,
    manifest: Option<&Path>,
) -> Vec<TargetQualityGateConfig> {
    let name = |suffix: &str| match managed_index {
        Some(index) => format!("managed-{index}-rust-{suffix}"),
        None => format!("rust-{suffix}"),
    };
    let manifest_arguments = || {
        manifest.map_or_else(Vec::new, |path| {
            vec![
                "--manifest-path".to_string(),
                path.to_string_lossy().into_owned(),
            ]
        })
    };
    vec![
        TargetQualityGateConfig {
            name: name("format"),
            argv: ["cargo", "fmt"]
                .map(str::to_string)
                .into_iter()
                .chain(manifest_arguments())
                .chain(["--all".to_string(), "--check".to_string()])
                .collect(),
        },
        TargetQualityGateConfig {
            name: name("test"),
            argv: ["cargo", "test"]
                .map(str::to_string)
                .into_iter()
                .chain(manifest_arguments())
                .chain(["--workspace".to_string()])
                .collect(),
        },
        TargetQualityGateConfig {
            name: name("clippy"),
            argv: ["cargo", "clippy"]
                .map(str::to_string)
                .into_iter()
                .chain(manifest_arguments())
                .chain(["--workspace", "--all-targets", "--", "-D", "warnings"].map(str::to_string))
                .collect(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn infers_manifest_scoped_gates_for_managed_rust_projects() {
        let repository = tempfile::tempdir().unwrap();
        let target = repository.path().join("backend-rs-intra");
        let sibling = repository.path().join("backend-rs");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("Cargo.toml"), "[workspace]\n").unwrap();

        let inferred =
            inferred_target_quality_gates(&target, &[std::path::PathBuf::from("../backend-rs")]);

        assert_eq!(inferred.len(), 3);
        assert_eq!(
            inferred
                .iter()
                .map(|gate| gate.name.as_str())
                .collect::<Vec<_>>(),
            [
                "managed-1-rust-format",
                "managed-1-rust-test",
                "managed-1-rust-clippy"
            ]
        );
        assert_eq!(
            inferred[1].argv,
            [
                "cargo",
                "test",
                "--manifest-path",
                "../backend-rs/Cargo.toml",
                "--workspace"
            ]
        );
    }
}
