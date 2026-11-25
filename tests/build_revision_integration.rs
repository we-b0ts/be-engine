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

fn build_script(binary: &Path, manifest_dir: &Path, compiled_dir: &Path, package: &str) -> Command {
    let mut command = Command::new(binary);
    command
        .current_dir(compiled_dir)
        .env("CARGO_MANIFEST_DIR", manifest_dir)
        .env("CARGO_PKG_NAME", package)
        .env_remove("TRAFFIC_E2E_BUILD_REVISION")
        .env_remove("TRAFFIC_E2E_TARGET_BUILDER_IMAGE")
        .env_remove("TRAFFIC_E2E_TARGET_RUNTIME_IMAGE");
    command
}

fn run_build_script(command: &mut Command) -> String {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
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
    let mut cli = build_script(&binary, &current, &compiled, "traffic-e2e");
    let output = run_build_script(&mut cli);
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

    std::fs::write(current.join("tracked.txt"), "modified").unwrap();
    let output = run_build_script(&mut cli);
    assert!(
        output.contains(&format!("revision {expected}-dirty;")),
        "{output}"
    );
    assert!(
        output.contains(&format!("engine-revision-v1:{expected}\n")),
        "{output}"
    );
    git(&current, &["checkout", "--", "tracked.txt"]);
    let output = run_build_script(&mut cli);
    assert!(
        output.contains(&format!("revision {expected};")),
        "{output}"
    );

    let member = current.join("engine-e2e-run");
    std::fs::create_dir_all(member.join("src")).unwrap();
    let engine = current.join("engine");
    std::fs::create_dir(&engine).unwrap();
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "engine-e2e-run/Cargo.toml",
    ] {
        std::fs::write(current.join(name), "").unwrap();
    }
    let output = run_build_script(&mut cli);
    for name in ["Cargo.toml", "Cargo.lock", "build.rs", "engine-e2e-run/src"] {
        assert!(
            output
                .lines()
                .any(|line| line
                    == format!("cargo:rerun-if-changed={}", current.join(name).display())),
            "{output}"
        );
    }
    let mut runner = build_script(&binary, &member, &compiled, "traffic-engine-e2e-run");
    let output = run_build_script(&mut runner);
    assert_eq!(watched_workspace_paths(&output, &current), ["build.rs"]);
    assert!(
        output.contains(&format!("revision {expected};")),
        "{output}"
    );
    assert!(
        output.contains(&format!("engine-revision-v1:{expected}\n")),
        "{output}"
    );

    git(&current, &["pack-refs", "--all", "--prune"]);
    let output = run_build_script(&mut runner);
    assert!(output.contains("packed-refs"), "{output}");
    for path in output
        .lines()
        .filter_map(|line| line.strip_prefix("cargo:rerun-if-changed="))
    {
        assert!(Path::new(path).exists(), "{output}");
    }

    let output = run_build_script(cli.env("TRAFFIC_E2E_BUILD_REVISION", " release-42-dirty "));
    assert_eq!(watched_workspace_paths(&output, &current), ["build.rs"]);
    assert!(output.contains("revision release-42-dirty;"), "{output}");
    assert!(
        output.contains("engine-revision-v1:release-42\n"),
        "{output}"
    );
    assert!(!output.contains(".git/HEAD"), "{output}");

    let output = run_build_script(
        build_script(&binary, &engine, &compiled, "traffic-engine")
            .env("TRAFFIC_E2E_TARGET_BUILDER_IMAGE", "builder:custom")
            .env("TRAFFIC_E2E_TARGET_RUNTIME_IMAGE", "runtime:custom"),
    );
    assert_eq!(watched_workspace_paths(&output, &current), ["build.rs"]);
    assert!(
        output.contains("TRAFFIC_E2E_TARGET_BUILDER_IMAGE=builder:custom"),
        "{output}"
    );
    assert!(
        output.contains("TRAFFIC_E2E_TARGET_RUNTIME_IMAGE=runtime:custom"),
        "{output}"
    );
    assert!(!output.contains(".git/HEAD"), "{output}");
}

fn watched_workspace_paths(output: &str, root: &Path) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| line.strip_prefix("cargo:rerun-if-changed="))
        .filter_map(|path| Path::new(path).canonicalize().ok())
        .filter_map(|path| {
            let relative = path.strip_prefix(root).ok()?;
            (!relative.starts_with(".git")).then(|| relative.to_string_lossy().into_owned())
        })
        .collect()
}
