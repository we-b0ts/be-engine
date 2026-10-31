//! Authenticated references into immutable semantic recordings. Native owners
//! reconstruct their exact envelopes; this layer never normalizes their values.
use super::*;
use crate::dependency_index::{FileStamp, RecordLocation, RecordReader};
use crate::policy::Protocol;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SourceRecord {
    pub path: PathBuf,
    pub stamp: FileStamp,
    pub location: RecordLocation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<(PathBuf, FileStamp)>,
}

impl SourceRecord {
    pub(crate) fn from_source(
        source: &crate::dependency_index::scoped::Source,
        stamp: FileStamp,
        location: RecordLocation,
    ) -> Self {
        Self {
            path: source.path.clone(),
            stamp,
            location,
            view: source.view.clone(),
        }
    }

    fn source(&self) -> crate::dependency_index::scoped::Source {
        crate::dependency_index::scoped::Source {
            path: self.path.clone(),
            locations: None,
            view: self.view.clone(),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.source().validate()?;
        ensure!(
            FileStamp::read_native(&self.path)? == self.stamp,
            "referenced Source evidence changed after Replay"
        );
        Ok(())
    }

    pub(crate) fn read(&self) -> Result<std::sync::Arc<Vec<u8>>> {
        RecordReader::new(0).read_source(&self.source(), &self.stamp, &self.location)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct SourcePayload {
    pub record: SourceRecord,
    pub protocol: Protocol,
    pub surface: Surface,
}

impl SourcePayload {
    pub(super) fn read(&self, context: &Path) -> Result<Vec<u8>> {
        let bytes = self.record.read()?;
        let event: Value = serde_json::from_slice(&bytes)?;
        match self.protocol {
            Protocol::Mysql => crate::replay::mysql_source_witness(&event, self.surface),
            Protocol::Http => crate::replay::http_source_witness(&event, self.surface, context),
            Protocol::Memcached => crate::replay::memcached_source_witness(&event, self.surface),
            Protocol::Redis if self.surface == Surface::DependencyRequest => {
                let args = event["args"]
                    .as_array()
                    .context("Source Redis arguments missing")?
                    .iter()
                    .map(decode)
                    .collect::<Result<Vec<_>>>()?;
                Ok(serde_json::to_vec(&args)?)
            }
            Protocol::Redis => decode(&event["response"]),
        }
    }
}

fn decode(value: &Value) -> Result<Vec<u8>> {
    ensure!(value["truncated"] == false, "Source payload is incomplete");
    let data = value["data"].as_str().context("Source payload missing")?;
    match value["encoding"].as_str() {
        Some("base64") => Ok(STANDARD.decode(data)?),
        Some("utf8") => Ok(data.as_bytes().to_vec()),
        _ => anyhow::bail!("unsupported Source payload encoding"),
    }
}

pub(super) fn identity(metadata: &SourceIdentity, protocol: Protocol) -> Result<String> {
    Ok(serde_json::to_string(&(metadata, protocol))?)
}
