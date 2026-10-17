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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct SourcePayload {
    pub record: SourceRecord,
    pub protocol: Protocol,
    pub surface: Surface,
}

impl SourcePayload {
    pub(super) fn read(&self, context: &Path) -> Result<Vec<u8>> {
        let bytes = RecordReader::new(0).read(
            &self.record.path,
            &self.record.stamp,
            &self.record.location,
        )?;
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
