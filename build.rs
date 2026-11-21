use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const BUILD_REVISION_ENV: &str = "TRAFFIC_E2E_BUILD_REVISION";
const DEFAULT_TARGET_BUILDER_IMAGE: &str = "docker.io/library/rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e";
const DEFAULT_TARGET_RUNTIME_IMAGE: &str = "be-engine-target-runtime:local";

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_MANIFEST_DIR");
    let package = env::var("CARGO_PKG_NAME").expect("Cargo must provide the package name");
    let manifest_root = manifest_dir();
    let workspace_root = manifest_root
        .ancestors()
        .find(|path| path.join("build.rs").is_file() && path.join("Cargo.lock").is_file())
        .unwrap_or(&manifest_root);
    let build_script = workspace_root.join("build.rs");
    if build_script.is_file() {
        emit_rerun_path(build_script);
    }
    let target_runtime_image = image_reference(
        "TRAFFIC_E2E_TARGET_RUNTIME_IMAGE",
        DEFAULT_TARGET_RUNTIME_IMAGE,
    );
    println!("cargo:rustc-env=TRAFFIC_E2E_TARGET_RUNTIME_IMAGE={target_runtime_image}");

    if package == "traffic-engine" {
        let target_builder_image = image_reference(
            "TRAFFIC_E2E_TARGET_BUILDER_IMAGE",
            DEFAULT_TARGET_BUILDER_IMAGE,
        );
        println!("cargo:rustc-env=TRAFFIC_E2E_TARGET_BUILDER_IMAGE={target_builder_image}");
        return;
    }

    println!("cargo:rerun-if-env-changed={BUILD_REVISION_ENV}");
    let cli = package == "traffic-e2e";
    let revision = match env::var(BUILD_REVISION_ENV) {
        Ok(value) => validate_revision(value.trim(), BUILD_REVISION_ENV),
        Err(_) => {
            if cli {
                emit_workspace_rerun_paths(workspace_root);
            }
            emit_git_rerun_paths(cli);
            git_revision(cli)
        }
    };
    let version = format!(
        "{} (revision {revision}; target-runtime {target_runtime_image})",
        env!("CARGO_PKG_VERSION")
    );
    println!("cargo:rustc-env=TRAFFIC_E2E_BUILD_VERSION={version}");
    let fingerprint = format!("engine-revision-v1:{}", revision.trim_end_matches("-dirty"));
    println!("cargo:rustc-env=TRAFFIC_E2E_ENGINE_FINGERPRINT={fingerprint}");
}

fn image_reference(key: &str, default: &str) -> String {
    println!("cargo:rerun-if-env-changed={key}");
    let value = env::var(key).unwrap_or_else(|_| default.to_string());
    assert!(
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@')
            }),
        "{key} must be a Docker image reference"
    );
    value
}

fn git_revision(include_worktree: bool) -> String {
    let Some(mut revision) = git_output(&["rev-parse", "--short=12", "HEAD"]) else {
        return "unknown".to_string();
    };
    revision = validate_revision(&revision, "git revision");
    if include_worktree
        && git_output(&["status", "--porcelain", "--untracked-files=normal"])
            .is_some_and(|status| !status.is_empty())
    {
        revision.push_str("-dirty");
    }
    revision
}

fn validate_revision(revision: &str, source: &str) -> String {
    assert!(
        !revision.is_empty()
            && revision.len() <= 64
            && revision.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
            }),
        "{source} must be 1-64 ASCII letters, digits, '.', '_', '+', or '-'"
    );
    revision.to_string()
}

fn emit_git_rerun_paths(include_worktree: bool) {
    let Some(head) = git_path("HEAD") else {
        return;
    };
    emit_rerun_path(head);
    if let Some(reference) = git_output(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git_path(&reference)
    {
        // A packed branch has no loose ref until its next update.
        if let Some(existing) = path.ancestors().find(|ancestor| ancestor.exists()) {
            emit_rerun_path(existing);
        }
    }
    for name in ["packed-refs", "index"] {
        if (name != "index" || include_worktree)
            && let Some(path) = git_path(name).filter(|path| path.is_file())
        {
            emit_rerun_path(path);
        }
    }
}

fn emit_workspace_rerun_paths(root: &Path) {
    let mut inputs: Vec<_> = ["Cargo.toml", "Cargo.lock", "src", "tests"]
        .into_iter()
        .map(|path| root.join(path))
        .filter(|path| path.exists())
        .collect();
    for entry in std::fs::read_dir(root).expect("read workspace directory") {
        let member = entry.expect("read workspace entry").path();
        if member.join("Cargo.toml").is_file() {
            inputs.extend(
                ["Cargo.toml", "src", "tests"]
                    .into_iter()
                    .map(|path| member.join(path))
                    .filter(|path| path.exists()),
            );
        }
    }
    inputs.sort();
    for path in inputs {
        emit_rerun_path(path);
    }
}

fn git_path(name: &str) -> Option<PathBuf> {
    git_output(&["rev-parse", "--git-path", name]).map(|path| resolve_path(&path))
}

fn resolve_path(path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        manifest_dir().join(path)
    }
}

fn emit_rerun_path(path: impl AsRef<Path>) {
    println!("cargo:rerun-if-changed={}", path.as_ref().display());
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(manifest_dir())
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn manifest_dir() -> PathBuf {
    env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("Cargo must provide the current manifest directory when running its build script")
}
