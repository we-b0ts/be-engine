//! In-memory native fixtures fail explicitly if stored payload access is requested.
#[derive(Debug, Clone)]
pub(crate) struct NoSource;
impl traffic_protocol::evidence::RecordSource for NoSource {
    fn load<T: serde::de::DeserializeOwned>(&self) -> anyhow::Result<T> {
        anyhow::bail!("native in-memory fixture has no stored payload")
    }
}
