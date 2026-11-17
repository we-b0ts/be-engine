//! Test callers use the same immutable scope resolver as production readers.
use std::path::Path;

pub async fn read_to_string(path: impl AsRef<Path>) -> std::io::Result<String> {
    let path = path.as_ref();
    if path.file_name().is_some_and(|n| {
        n == "dependencies.jsonl"
            || n == "global-dependencies.jsonl"
            || n.to_string_lossy().ends_with("-scope.json")
    }) {
        return crate::dependency_index::scoped::read_bytes(path)
            .map_err(io_error)
            .and_then(|bytes| String::from_utf8(bytes).map_err(std::io::Error::other));
    }
    if path
        .file_name()
        .is_some_and(|n| n == "dependencies-debug.jsonl" || n == "global-dependencies-debug.jsonl")
        && let Some(root) = path
            .ancestors()
            .find(|p| p.join("recording-run.json").is_file())
    {
        return tokio::fs::read_to_string(root.join("dependencies-debug.jsonl")).await;
    }
    tokio::fs::read_to_string(path).await
}

fn io_error(error: anyhow::Error) -> std::io::Error {
    match error.downcast::<std::io::Error>() {
        Ok(error) => error,
        Err(error) => std::io::Error::other(error),
    }
}

pub fn read_to_string_sync(path: impl AsRef<Path>) -> std::io::Result<String> {
    let path = path.as_ref();
    if path.file_name().is_some_and(|n| {
        n == "dependencies.jsonl"
            || n == "global-dependencies.jsonl"
            || n.to_string_lossy().ends_with("-scope.json")
    }) {
        return crate::dependency_index::scoped::read_bytes(path)
            .map_err(io_error)
            .and_then(|bytes| String::from_utf8(bytes).map_err(std::io::Error::other));
    }
    std::fs::read_to_string(path)
}
