use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::model::*;

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn http_key(host: &str, port: u16, method: &str, path: &str) -> String {
    digest(
        &serde_json::to_vec(&(
            host.trim_end_matches('.').to_ascii_lowercase(),
            port,
            method.to_ascii_uppercase(),
            path,
        ))
        .expect("selector serializes"),
    )
}

pub(crate) fn redis_key(
    host: &str,
    port: u16,
    database: i64,
    command: &str,
    args: &[Vec<u8>],
) -> String {
    digest(
        &serde_json::to_vec(&(
            host.trim_end_matches('.').to_ascii_lowercase(),
            port,
            database,
            command.to_ascii_uppercase(),
            args,
        ))
        .expect("selector serializes"),
    )
}

pub(crate) fn http_endpoint(value: &Value) -> Result<Endpoint> {
    let scheme = match value["scheme"]
        .as_str()
        .context("HTTP evidence lacks scheme")?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "http" | "fake_ip_http" | "http_gateway" => "http",
        "https" | "fake_ip_https" => "https",
        _ => anyhow::bail!("invalid HTTP evidence scheme"),
    };
    let authority = value["authority"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .context("HTTP evidence lacks authority")?
        .parse::<hyper::http::uri::Authority>()?;
    Ok(Endpoint {
        host: authority.host().trim_end_matches('.').to_ascii_lowercase(),
        port: authority
            .port_u16()
            .unwrap_or(if scheme == "https" { 443 } else { 80 }),
        protocol: scheme.into(),
    })
}

pub(crate) struct Builder {
    index: FileIndex,
    endpoints: BTreeSet<Endpoint>,
    hash: Sha256,
    offset: u64,
}

impl Builder {
    pub(crate) fn new(stamp: FileStamp) -> Self {
        Self {
            index: FileIndex {
                version: VERSION,
                stamp,
                sha256: String::new(),
                events: 0,
                endpoints: Vec::new(),
                metadata: Vec::new(),
                http: Vec::new(),
                redis: Vec::new(),
                mysql: None,
                redis_lanes: Default::default(),
            },
            endpoints: BTreeSet::new(),
            hash: Sha256::new(),
            offset: 0,
        }
    }

    /// Observe exact on-disk bytes, including their line terminator.
    pub(crate) fn observe(&mut self, line: usize, raw: &[u8], value: Option<&Value>) -> Result<()> {
        let offset = self.offset;
        self.hash.update(raw);
        self.offset += raw.len() as u64;
        let Some(value) = value else {
            return Ok(());
        };
        self.index.events += 1;
        let tag = value["event_type"].as_str().unwrap_or_default();
        let location = if matches!(
            tag,
            "http_exchange" | "redis_exchange" | "redis_pub_sub_push"
        ) {
            Some(RecordLocation {
                line,
                offset,
                length: raw.len() as u64,
                sha256: digest(raw),
            })
        } else {
            None
        };
        if tag.ends_with("_connection") || tag == "proxy_error" {
            self.index.metadata.push((line, value.clone()));
        }
        if tag == "http_exchange" {
            let endpoint = http_endpoint(value)?;
            let uri: hyper::Uri = value["uri"].as_str().context("HTTP URI missing")?.parse()?;
            let key = http_key(
                &endpoint.host,
                endpoint.port,
                value["method"].as_str().context("HTTP method missing")?,
                uri.path(),
            );
            self.endpoints.insert(endpoint);
            if let Some(discovered) = value["discovered_tcp_targets"].as_array() {
                for target in discovered {
                    self.index.metadata.push((line, serde_json::json!({"event_type": "indexed_advertised_target", "target": target})));
                }
            }
            self.index.http.push(IndexedRecord {
                location: location.expect("HTTP record location"),
                key,
                connection_id: None,
            });
        } else {
            let mysql_skipped = tag == "mysql_exchange"
                && (crate::mysql::wire::is_no_response_command(
                    value["command"].as_str().unwrap_or_default(),
                ) || value["command"] == "COM_STMT_PREPARE"
                    && value["response"]["status"] == "stmt_prepare");
            let has_endpoint = matches!(
                tag,
                "mysql_connection"
                    | "mysql_exchange"
                    | "redis_connection"
                    | "redis_exchange"
                    | "redis_pub_sub_push"
                    | "memcached_connection"
                    | "memcached_exchange"
                    | "kafka_connection"
                    | "kafka_produce"
                    | "kafka_fetch"
                    | "kafka_delivery"
                    | "motan_connection"
                    | "motan_exchange"
            ) && !mysql_skipped;
            if has_endpoint
                && let (Some(host), Some(port)) =
                    (value["target_host"].as_str(), value["target_port"].as_u64())
            {
                let protocol = tag.split('_').next().unwrap_or_default();
                if matches!(
                    protocol,
                    "mysql" | "redis" | "memcached" | "kafka" | "motan"
                ) {
                    self.endpoints.insert(Endpoint {
                        host: host.trim_end_matches('.').to_ascii_lowercase(),
                        port: u16::try_from(port)?,
                        protocol: protocol.into(),
                    });
                }
            }
            if tag == "motan_exchange" && value["advertised_ip"].is_string() {
                self.index.metadata.push((line, serde_json::json!({"event_type": "indexed_advertised_target", "target": {
                    "alias": value["target_host"], "port": value["target_port"], "protocol": "motan", "advertised_ip": value["advertised_ip"]
                }})));
            }
            if has_endpoint
                && tag.starts_with("mysql_")
                && value["target_host"]
                    .as_str()
                    .zip(value["target_port"].as_u64())
                    .is_none()
                && let Some(address) = value["target_addr"]
                    .as_str()
                    .map(str::trim)
                    .and_then(|s| s.parse::<hyper::http::uri::Authority>().ok())
                && let Some(port) = address.port_u16()
            {
                self.endpoints.insert(Endpoint {
                    host: address
                        .host()
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .trim_end_matches('.')
                        .to_ascii_lowercase(),
                    port,
                    protocol: "mysql".into(),
                });
            }
            if tag == "redis_pub_sub_push" {
                self.index.redis.push(IndexedRecord {
                    location: location.clone().expect("Pub/Sub location"),
                    key: digest(raw),
                    connection_id: value["connection_id"].as_str().map(str::to_owned),
                });
            }
            if tag == "redis_exchange" {
                let connection = value["connection_id"]
                    .as_str()
                    .context("Redis connection identity missing")?
                    .to_owned();
                *self
                    .index
                    .redis_lanes
                    .entry(connection.clone())
                    .or_default() += 1;
                // Hash exact decoded command arguments. Values never enter the index.
                let args = value["args"]
                    .as_array()
                    .context("Redis arguments missing")?
                    .iter()
                    .map(decode_capture)
                    .collect::<Result<Vec<_>>>()?;
                let key = redis_key(
                    value["target_host"]
                        .as_str()
                        .context("Redis host missing")?,
                    u16::try_from(
                        value["target_port"]
                            .as_u64()
                            .context("Redis port missing")?,
                    )?,
                    value["database"]
                        .as_i64()
                        .context("Redis database missing")?,
                    value["command"].as_str().context("Redis command missing")?,
                    &args,
                );
                self.index.redis.push(IndexedRecord {
                    location: location.expect("Redis record location"),
                    key,
                    connection_id: Some(connection),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<FileIndex> {
        ensure!(
            self.offset == self.index.stamp.size,
            "dependency file changed while building index"
        );
        self.index.sha256 = format!("{:x}", self.hash.finalize());
        self.index.endpoints = self.endpoints.into_iter().collect();
        Ok(self.index)
    }
}

fn decode_capture(value: &Value) -> Result<Vec<u8>> {
    // Retain unsafe/truncated records as candidates; eligibility is checked by Replay.
    let data = value["data"]
        .as_str()
        .context("Redis capture data missing")?;
    match value["encoding"].as_str() {
        Some("utf8") => Ok(data.as_bytes().to_vec()),
        Some("base64") => Ok(base64::engine::general_purpose::STANDARD.decode(data)?),
        _ => anyhow::bail!("unsupported Redis argument capture encoding"),
    }
}

pub(crate) fn build_file(
    path: &Path,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<FileIndex> {
    let stamp = FileStamp::read(path)?;
    let mut builder = Builder::new(stamp.clone());
    let mut input = BufReader::new(File::open(path)?);
    let mut raw = Vec::new();
    let mut line = 0;
    while input.read_until(b'\n', &mut raw)? != 0 {
        super::store::check_cancelled(cancelled)?;
        line += 1;
        let value = if raw.iter().all(u8::is_ascii_whitespace) {
            None
        } else {
            Some(serde_json::from_slice::<Value>(&raw).with_context(|| {
                format!("invalid dependency evidence {} line {line}", path.display())
            })?)
        };
        builder.observe(line, &raw, value.as_ref())?;
        raw.clear();
    }
    ensure!(
        FileStamp::read(path)? == stamp,
        "dependency file changed while building index"
    );
    builder.finish()
}
