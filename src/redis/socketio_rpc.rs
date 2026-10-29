//! Bounded Socket.IO Redis-adapter RPC envelopes; no application event semantics.
use anyhow::{Context, Result, ensure};
use serde_json::Value;

pub(crate) const MAX_RPC_BYTES: usize = crate::value_limits::MAX_VALUE_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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

/// The native envelope identity only; application data stays in its original record.
pub(crate) fn notification_request(channel: &[u8], payload: &[u8]) -> Option<Identity> {
    request("PUBLISH", &[channel.to_vec(), payload.to_vec()])
        .ok()
        .flatten()
        .map(|request| request.identity)
}

/// Bounded protocol metadata only; ordinary broadcast arguments stay private.
pub(crate) fn notification_namespace(channel: &[u8], payload: &[u8]) -> Option<String> {
    broadcast("PUBLISH", &[channel.to_vec(), payload.to_vec()])
        .ok()
        .flatten()?
        .value["namespace"]
        .as_str()
        .map(str::to_owned)
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
    /// Application contracts select data only. Every other envelope member
    /// remains exact except the identities verified by the RPC adapter.
    pub fn envelope_matches(&self, actual: &Self) -> bool {
        let (Some(source), Some(target)) = (self.value.as_object(), actual.value.as_object())
        else {
            return false;
        };
        source.len() == target.len()
            && source.iter().all(|(name, value)| {
                matches!(name.as_str(), "data" | "host_id" | "callback" | "room")
                    || target.get(name) == Some(value)
            })
    }

    pub fn comparison_value(&self, actual: &Self) -> Value {
        let mut expected = self.value.clone();
        expected["host_id"] = actual.value["host_id"].clone();
        expected["room"] = actual.value["room"].clone();
        expected["callback"][0] = actual.value["callback"][0].clone();
        expected["callback"][2] = actual.value["callback"][2].clone();
        expected
    }
}

/// Exact Redis self-echo identity; protocol IDs and application bytes are included.
pub(crate) fn echo_digest(channel: &[u8], payload: &[u8]) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    if payload.len() > MAX_RPC_BYTES || channel.is_empty() || channel.len() > 1024 {
        return None;
    }
    let args = [channel.to_vec(), payload.to_vec()];
    if request("PUBLISH", &args).ok().flatten().is_none()
        && broadcast("PUBLISH", &args).ok().flatten().is_none()
    {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update((channel.len() as u64).to_be_bytes());
    hash.update(channel);
    hash.update(payload);
    Some(hash.finalize().into())
}

/// A non-RPC Socket.IO broadcast still carries the manager's process identity.
#[derive(Debug, Clone)]
pub(crate) struct Broadcast {
    pub host: String,
    pub value: Value,
}

pub(crate) fn broadcast(command: &str, args: &[Vec<u8>]) -> Result<Option<Broadcast>> {
    if command != "PUBLISH" || args.len() != 2 {
        return Ok(None);
    }
    let Some(value) = document(&args[1]) else {
        return Ok(None);
    };
    if value["method"] != "emit" || value.get("callback") != Some(&Value::Null) {
        return Ok(None);
    }
    ensure!(
        !args[0].is_empty() && args[0].len() <= 1024,
        "invalid adapter channel"
    );
    ensure!(
        value["binary"] == false && value["data"].is_array(),
        "adapter requires non-binary JSON arguments"
    );
    text(&value["event"])?;
    text(&value["namespace"])?;
    ensure!(
        value["room"].is_null() || value["room"].is_string(),
        "invalid adapter room"
    );
    Ok(Some(Broadcast {
        host: host(&value["host_id"])?,
        value,
    }))
}

impl Broadcast {
    pub fn envelope_matches(&self, actual: &Self) -> bool {
        let (Some(source), Some(target)) = (self.value.as_object(), actual.value.as_object())
        else {
            return false;
        };
        source.len() == target.len()
            && source.iter().all(|(name, value)| {
                matches!(name.as_str(), "data" | "host_id") || target.get(name) == Some(value)
            })
    }
    pub fn comparison_value(&self, actual: &Self) -> Value {
        let mut expected = self.value.clone();
        expected["host_id"] = actual.value["host_id"].clone();
        expected
    }
}
