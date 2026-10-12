use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const BUILD_REVISION_ENV: &str = "TRAFFIC_E2E_BUILD_REVISION";
const TARGET_RUNTIME_IMAGE: &str = "registry.api.demo.test/weibo_rd_if/traffic-e2e-rust-runtime:0.0.2@sha256:d322b050229334c2fec00cdce366a066697a7bafaf9b6842d77793eb1e4f10d2";

fn main() {
    println!("cargo:rerun-if-env-changed={BUILD_REVISION_ENV}");
    for path in ["build.rs", "Cargo.toml", "Cargo.lock", "src"] {
        println!("cargo:rerun-if-changed={path}");
    }
    emit_git_rerun_paths();

    let revision = env::var(BUILD_REVISION_ENV)
        .ok()
        .map(|value| validate_revision(value.trim(), BUILD_REVISION_ENV))
        .unwrap_or_else(git_revision);
    let version = format!(
        "{} (revision {revision}; target-runtime {TARGET_RUNTIME_IMAGE})",
        env!("CARGO_PKG_VERSION")
    );
    println!("cargo:rustc-env=TRAFFIC_E2E_BUILD_VERSION={version}");
    let fingerprint = format!("engine-revision-v1:{}", revision.trim_end_matches("-dirty"));
    println!("cargo:rustc-env=TRAFFIC_E2E_ENGINE_FINGERPRINT={fingerprint}");
    println!("cargo:rustc-env=TRAFFIC_E2E_TARGET_RUNTIME_IMAGE={TARGET_RUNTIME_IMAGE}");
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
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
    };
    println!("cargo:rerun-if-changed={}", path.display());
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}
