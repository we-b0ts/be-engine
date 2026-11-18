//! Shared durable recorder artifact writes.
pub(super) use traffic_recorder::storage::{append, write};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_and_read_preserve_artifact_contents() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("artifact.json");

        write(&path, b"{\"ok\":true}\n").await.unwrap();
        let contents = crate::recorder::test_io::read_to_string(&path)
            .await
            .unwrap();

        assert_eq!(contents, "{\"ok\":true}\n");
    }

    #[tokio::test]
    async fn append_preserves_existing_artifact_contents() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("errors.jsonl");

        append(&path, b"first\n").await.unwrap();
        append(&path, b"second\n").await.unwrap();

        assert_eq!(
            crate::recorder::test_io::read_to_string(path)
                .await
                .unwrap(),
            "first\nsecond\n"
        );
    }
}
