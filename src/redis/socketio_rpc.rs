//! Bounded Socket.IO Redis-adapter RPC envelopes; no application event semantics.
use anyhow::{Context, Result, ensure};
use serde_json::Value;

pub(crate) const MAX_RPC_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Identity {
    pub host: String,
    pub sid: String,
    pub namespace: String,
    pub id: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub identity: Identity,
    pub value: Value,
}

fn document(bytes: &[u8]) -> Option<Value> {
    if bytes.len() > MAX_RPC_BYTES || bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
    {
        return None;
    }
    crate::json_value::parse(bytes)
}

fn text(value: &Value) -> Result<String> {
    let value = value.as_str().context("RPC identity must be a string")?;
    ensure!(
        !value.is_empty() && value.len() <= 1024,
        "invalid RPC identity length"
    );
    Ok(value.to_owned())
}

fn host(value: &Value) -> Result<String> {
    let value = text(value)?;
    let uuid = uuid::Uuid::parse_str(&value).context("RPC host_id must be UUID v4 hex")?;
    ensure!(
        value.len() == 32
            && uuid.get_version() == Some(uuid::Version::Random)
            && uuid.get_variant() == uuid::Variant::RFC4122,
        "RPC host_id must be UUID v4 hex"
    );
    Ok(value)
}

pub(crate) fn request(command: &str, args: &[Vec<u8>]) -> Result<Option<Request>> {
    if command != "PUBLISH" || args.len() != 2 {
        return Ok(None);
    }
    let Some(value) = document(&args[1]) else {
        return Ok(None);
    };
    if value["method"] != "emit" || value["callback"].is_null() {
        return Ok(None);
    }
    ensure!(
        args[0].len() <= 1024 && !args[0].is_empty(),
        "invalid RPC channel"
    );
    ensure!(
        value["binary"] == false && value["data"].is_array(),
        "RPC requires non-binary JSON arguments"
    );
    text(&value["event"])?;
    let callback = value["callback"]
        .as_array()
        .context("RPC callback must be an array")?;
    ensure!(
        callback.len() == 3,
        "RPC callback must contain sid, namespace and id"
    );
    let identity = Identity {
        host: host(&value["host_id"])?,
        sid: text(&callback[0])?,
        namespace: text(&callback[1])?,
        id: callback[2]
            .as_u64()
            .filter(|id| *id > 0)
            .context("RPC callback id must be positive")?,
    };
    ensure!(
        value["room"] == identity.sid && value["namespace"] == identity.namespace,
        "RPC callback does not match room/namespace"
    );
    Ok(Some(Request { identity, value }))
}

pub(crate) fn callback(payload: &[u8]) -> Result<Option<(Identity, Value)>> {
    let Some(value) = document(payload) else {
        return Ok(None);
    };
    if value["method"] != "callback" {
        return Ok(None);
    }
    ensure!(
        value["args"].is_array(),
        "RPC callback arguments must be an array"
    );
    let identity = Identity {
        host: host(&value["host_id"])?,
        sid: text(&value["sid"])?,
        namespace: text(&value["namespace"])?,
        id: value["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .context("invalid RPC callback id")?,
    };
    Ok(Some((identity, value)))
}

impl Request {
    pub fn matches(&self, actual: &Self) -> bool {
        let mut expected = self.value.clone();
        expected["host_id"] = actual.value["host_id"].clone();
        expected["callback"][2] = actual.value["callback"][2].clone();
        expected == actual.value
    }
}
