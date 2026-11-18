use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

const REWRITE_BINARY_NAME: &str = "backend-rewrite";
const ENGINE_BINARY_NAME: &str = "traffic-e2e";

pub fn executable() -> Result<PathBuf> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(executable) = recorded_test_engine()? {
        return Ok(executable);
    }
    let current = std::env::current_exe().context("failed to resolve current executable")?;
    resolve_executable(&current, std::process::id())
}

/// An installed filesystem path for container mounts, rather than a reexec handle.
pub fn installed_executable() -> Result<PathBuf> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(executable) = recorded_test_engine()? {
        return Ok(executable);
    }
    let current = std::env::current_exe().context("failed to resolve current executable")?;
    companion_or_self(installed_executable_path(&current))
}

#[cfg(any(test, feature = "test-support"))]
fn recorded_test_engine() -> Result<Option<PathBuf>> {
    let Some(path) = std::env::var_os("TRAFFIC_E2E_TEST_ENGINE_BINARY") else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    ensure!(
        path.is_absolute() && path.is_file(),
        "recorded test engine must be an existing absolute executable path"
    );
    Ok(Some(path))
}

fn resolve_executable(current: &Path, process_id: u32) -> Result<PathBuf> {
    let installed = installed_executable_path(current);
    #[cfg(target_os = "linux")]
    if installed
        .file_name()
        .is_some_and(|name| name == ENGINE_BINARY_NAME)
    {
        // Pin the running inode before an atomic replacement can race with
        // spawn. Use this process's PID so sudo resolves the engine,
        // rather than its own /proc/self/exe.
        return Ok(PathBuf::from(format!("/proc/{process_id}/exe")));
    }
    let _ = process_id;
    companion_or_self(installed)
}

fn companion_or_self(installed: PathBuf) -> Result<PathBuf> {
    let Some(engine) = companion_engine_path(&installed) else {
        return Ok(installed);
    };
    ensure!(
        engine.is_file(),
        "backend-rewrite requires the sibling traffic-e2e binary at {}",
        engine.display()
    );
    Ok(engine)
}

fn installed_executable_path(current: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    if let Some(name) = current
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(" (deleted)"))
        .filter(|name| matches!(*name, REWRITE_BINARY_NAME | ENGINE_BINARY_NAME))
    {
        return current.with_file_name(name);
    }
    current.to_path_buf()
}

fn companion_engine_path(current: &Path) -> Option<PathBuf> {
    (current.file_stem()?.to_str()? == REWRITE_BINARY_NAME).then(|| {
        let mut file_name = ENGINE_BINARY_NAME.to_string();
        if let Some(extension) = current.extension().and_then(|value| value.to_str()) {
            file_name.push('.');
            file_name.push_str(extension);
        }
        current.with_file_name(file_name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_rewrite_resolves_the_sibling_engine_binary() {
        assert_eq!(
            companion_engine_path(Path::new("/opt/bin/backend-rewrite")),
            Some(PathBuf::from("/opt/bin/traffic-e2e"))
        );
        assert_eq!(
            companion_engine_path(Path::new("C:/bin/backend-rewrite.exe")),
            Some(PathBuf::from("C:/bin/traffic-e2e.exe"))
        );
    }

    #[test]
    fn traffic_engine_and_test_binaries_resolve_themselves() {
        assert!(companion_engine_path(Path::new("/opt/bin/traffic-e2e")).is_none());
        assert!(companion_engine_path(Path::new("/tmp/traffic_e2e-tests")).is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn replaced_coordinator_still_resolves_its_installed_companion() {
        let root = tempfile::tempdir().unwrap();
        let engine = root.path().join(ENGINE_BINARY_NAME);
        let coordinator = root.path().join("backend-rewrite (deleted)");
        assert!(resolve_executable(&coordinator, std::process::id()).is_err());
        std::fs::write(&engine, "installed engine").unwrap();
        assert_eq!(
            resolve_executable(&coordinator, std::process::id()).unwrap(),
            engine
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn replaced_engine_uses_its_live_inode_without_requiring_a_replacement_file() {
        assert_eq!(
            resolve_executable(Path::new("/opt/traffic-e2e"), 1234).unwrap(),
            PathBuf::from("/proc/1234/exe")
        );
        assert_eq!(
            resolve_executable(Path::new("/removed/traffic-e2e (deleted)"), 1234).unwrap(),
            PathBuf::from("/proc/1234/exe")
        );
        assert_eq!(
            resolve_executable(Path::new("/opt/other (deleted)"), 1234).unwrap(),
            PathBuf::from("/opt/other (deleted)")
        );
        // Container bind mounts retain an installed path, not a host PID handle.
        assert_eq!(
            companion_or_self(installed_executable_path(Path::new(
                "/opt/traffic-e2e (deleted)"
            )))
            .unwrap(),
            PathBuf::from("/opt/traffic-e2e")
        );
    }

    #[cfg(target_os = "linux")]
    mod unlinked;
}
