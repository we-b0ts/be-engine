//! Ambient incoming notifications retain original ownership and physical slots.
use super::*;

/// Load only the immutable notification section. Unattributed outgoing commands,
/// queries and HTTP calls never become executable dependencies through this path.
pub(crate) async fn load(
    path: &Path,
    redis: &mut redis::RedisReplayState,
    reader: Arc<std::sync::Mutex<RecordReader>>,
) -> Result<()> {
    let source_path = path.to_owned();
    let (index, root) = tokio::task::spawn_blocking(move || {
        crate::dependency_index::global::load_global_index(&source_path, validate_index_record)
    })
    .await
    .context("ambient notification index preparation failed")??;
    let source = RecordSource::new(path, index.stamp.clone(), reader);
    redis.pubsub.restore_indexed(
        index.notifications.clone(),
        &root,
        source,
        ReplaySource::Unattributed,
    )
}
