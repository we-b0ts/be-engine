use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

const REWRITE_BINARY_NAME: &str = "backend-rewrite";
const ENGINE_BINARY_NAME: &str = "traffic-e2e";

pub(crate) fn executable() -> Result<PathBuf> {
    let current = std::env::current_exe().context("failed to resolve current executable")?;
    let Some(engine) = companion_engine_path(&current) else {
        return Ok(current);
    };
    ensure!(
        engine.is_file(),
        "backend-rewrite requires the sibling traffic-e2e binary at {}",
        engine.display()
    );
    Ok(engine)
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
}
