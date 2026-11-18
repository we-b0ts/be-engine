use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const BUILD_REVISION_ENV: &str = "TRAFFIC_E2E_BUILD_REVISION";
const DEFAULT_TARGET_BUILDER_IMAGE: &str = "docker.io/library/rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e";
const DEFAULT_TARGET_RUNTIME_IMAGE: &str = "be-engine-target-runtime:local";

fn main() {
    println!("cargo:rerun-if-env-changed={BUILD_REVISION_ENV}");
    println!("cargo:rerun-if-env-changed=CARGO_MANIFEST_DIR");
    let target_builder_image = image_reference(
        "TRAFFIC_E2E_TARGET_BUILDER_IMAGE",
        DEFAULT_TARGET_BUILDER_IMAGE,
    );
    let target_runtime_image = image_reference(
        "TRAFFIC_E2E_TARGET_RUNTIME_IMAGE",
        DEFAULT_TARGET_RUNTIME_IMAGE,
    );
    let manifest_root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let repository_root = if manifest_root.ends_with("crates/traffic-engine") {
        manifest_root.parent().unwrap().parent().unwrap()
    } else {
        &manifest_root
    };
    for path in ["build.rs", "Cargo.toml", "Cargo.lock", "src", "crates"] {
        println!(
            "cargo:rerun-if-changed={}",
            repository_root.join(path).display()
        );
    }
    emit_git_rerun_paths();

    let revision = env::var(BUILD_REVISION_ENV)
        .ok()
        .map(|value| validate_revision(value.trim(), BUILD_REVISION_ENV))
        .unwrap_or_else(git_revision);
    let version = format!(
        "{} (revision {revision}; target-runtime {target_runtime_image})",
        env!("CARGO_PKG_VERSION")
    );
    println!("cargo:rustc-env=TRAFFIC_E2E_BUILD_VERSION={version}");
    let fingerprint = format!("engine-revision-v1:{}", revision.trim_end_matches("-dirty"));
    println!("cargo:rustc-env=TRAFFIC_E2E_ENGINE_FINGERPRINT={fingerprint}");
    println!("cargo:rustc-env=TRAFFIC_E2E_TARGET_BUILDER_IMAGE={target_builder_image}");
    println!("cargo:rustc-env=TRAFFIC_E2E_TARGET_RUNTIME_IMAGE={target_runtime_image}");
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

fn git_revision() -> String {
    let Some(mut revision) = git_output(&["rev-parse", "--short=12", "HEAD"]) else {
        return "unknown".to_string();
    };
    revision = validate_revision(&revision, "git revision");
    if git_output(&["status", "--porcelain", "--untracked-files=normal"])
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

fn emit_git_rerun_paths() {
    let Some(head) = git_output(&["rev-parse", "--git-path", "HEAD"]) else {
        return;
    };
    emit_rerun_path(&head);
    if let Some(reference) = git_output(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git_output(&["rev-parse", "--git-path", &reference])
    {
        emit_rerun_path(&path);
    }
    if let Some(path) = git_output(&["rev-parse", "--git-path", "packed-refs"])
        && Path::new(&path).exists()
    {
        emit_rerun_path(&path);
    }
}

fn emit_rerun_path(path: &str) {
    let path = PathBuf::from(path);
    let path = if path.is_absolute() {
        path
    } else {
        manifest_dir().join(path)
    };
    println!("cargo:rerun-if-changed={}", path.display());
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(manifest_dir())
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
