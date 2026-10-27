//! Shared build-script executables must identify the checkout invoking Cargo.
use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}
fn checkout(root: &Path, text: &str) -> String {
    std::fs::create_dir_all(root).unwrap();
    git(root, &["init", "--quiet"]);
    std::fs::write(root.join("tracked.txt"), text).unwrap();
    git(root, &["add", "tracked.txt"]);
    git(
        root,
        &[
            "-c",
            "user.name=Build Tests",
            "-c",
            "user.email=build-tests@example.invalid",
            "commit",
            "--quiet",
            "-m",
            text,
        ],
    );
    git(root, &["rev-parse", "--short=12", "HEAD"])
}

#[test]
fn cached_build_script_uses_runtime_checkout_for_revision_and_git_watches() {
    let temp = tempfile::tempdir().unwrap();
    let compiled = temp.path().join("compiled-checkout");
    let current = temp.path().join("current-checkout");
    let old = checkout(&compiled, "compiled checkout");
    let expected = checkout(&current, "current checkout");
    assert_ne!(old, expected);
    let binary = temp.path().join("build-script");
    let status = Command::new("rustc")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs"))
        .args(["--edition=2024", "-o"])
        .arg(&binary)
        .env("CARGO_MANIFEST_DIR", &compiled)
        .env("CARGO_PKG_VERSION", env!("CARGO_PKG_VERSION"))
        .status()
        .unwrap();
    assert!(status.success());
    let output = Command::new(&binary)
        .current_dir(&compiled)
        .env("CARGO_MANIFEST_DIR", &current)
        .env_remove("TRAFFIC_E2E_BUILD_REVISION")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.contains(&format!("revision {expected};")),
        "{output}"
    );
    assert!(
        output.contains(&format!("engine-revision-v1:{expected}")),
        "{output}"
    );
    assert!(
        output.contains(&format!("{}/.git/HEAD", current.display())),
        "{output}"
    );
    assert!(
        !output.contains(&compiled.display().to_string()),
        "{output}"
    );
    assert!(!output.contains(&format!("revision {old};")), "{output}");
}
