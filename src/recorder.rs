use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use flate2::read::{GzDecoder, ZlibDecoder};
use hyper::HeaderMap;
use serde::Serialize;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
pub struct Recorder {
    file: Arc<Mutex<File>>,
    output_dir: Arc<std::path::PathBuf>,
    case_write_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BodyCapture {
    pub encoding: &'static str,
    pub original_len: usize,
    pub stored_len: usize,
    pub truncated: bool,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CaseBodyCapture {
    pub encoding: &'static str,
    pub original_len: usize,
    pub stored_len: usize,
    pub truncated: bool,
    pub decoded: bool,
    pub content_encoding: Option<String>,
    pub data: String,
    pub decode_error: Option<String>,
}

pub type HeaderMapSnapshot = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CaseContext {
    pub id: Uuid,
    pub rule_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum RecorderEvent {
    HttpExchange(HttpExchangeEvent),
    TcpGatewayConnection(TcpGatewayConnectionEvent),
    MysqlConnection(MysqlConnectionEvent),
    MysqlQuery(MysqlQueryEvent),
    MysqlResponse(MysqlResponseEvent),
    MysqlExchange(MysqlExchangeEvent),
    MysqlPacket(MysqlPacketEvent),
    MysqlTlsRejected(MysqlTlsRejectedEvent),
    ProxyError(ProxyErrorEvent),
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub comm: Option<String>,
    pub cmdline: Option<String>,
    pub exe: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpExchangeEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub client_process: Option<ProcessInfo>,
    pub scheme: String,
    pub method: String,
    pub uri: String,
    pub authority: Option<String>,
    pub request_headers: HeaderMapSnapshot,
    pub request_body: BodyCapture,
    pub response_status: Option<u16>,
    pub response_headers: Option<HeaderMapSnapshot>,
    pub response_body: Option<BodyCapture>,
    pub duration_ms: u128,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlConnectionEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub route_name: Option<String>,
    pub listen_addr: String,
    pub client_addr: Option<String>,
    pub client_process: Option<ProcessInfo>,
    pub upstream_addr: String,
    pub username: Option<String>,
    pub database: Option<String>,
    pub capability_flags: Option<u32>,
    pub duration_ms: Option<u128>,
    pub client_to_server_bytes: u64,
    pub server_to_client_bytes: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpGatewayConnectionEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub client_process: Option<ProcessInfo>,
    pub domain: Option<String>,
    pub fake_addr: String,
    pub upstream_addr: Option<String>,
    pub client_to_server_bytes: u64,
    pub server_to_client_bytes: u64,
    pub duration_ms: u128,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlQueryEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub client_process: Option<ProcessInfo>,
    pub command: String,
    pub query: Option<String>,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlPacketEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub query_sequence: Option<u64>,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub client_process: Option<ProcessInfo>,
    pub direction: String,
    pub sequence_id: u8,
    pub payload_len: usize,
    pub payload: Option<BodyCapture>,
    pub packet_kind: Option<String>,
    pub error_code: Option<u16>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlResponseEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub query_sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub client_process: Option<ProcessInfo>,
    pub status: String,
    pub packet_count: usize,
    pub payload_bytes: usize,
    pub duration_ms: u128,
    pub error_code: Option<u16>,
    pub error_message: Option<String>,
    pub payload: BodyCapture,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<Vec<MysqlResponsePacket>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlResponsePacket {
    pub sequence_id: u8,
    pub packet_kind: String,
    pub payload_len: usize,
    pub payload: BodyCapture,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlExchangeEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub query_sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub client_process: Option<ProcessInfo>,
    pub command: String,
    pub sql: Option<String>,
    pub statement_id: Option<u32>,
    pub params: Option<Vec<MysqlValue>>,
    pub response: MysqlExchangeResponse,
    pub duration_ms: u128,
    pub parse_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MysqlExchangeResponse {
    pub status: String,
    pub error_code: Option<u16>,
    pub error_message: Option<String>,
    pub affected_rows: Option<u64>,
    pub last_insert_id: Option<u64>,
    pub columns: Vec<MysqlColumn>,
    pub rows: Vec<Vec<MysqlValue>>,
    pub row_count: usize,
    pub rows_truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MysqlColumn {
    pub catalog: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub org_table: Option<String>,
    pub name: String,
    pub org_name: Option<String>,
    pub column_type: String,
    pub column_type_code: u8,
    pub charset: Option<u16>,
    pub column_length: Option<u32>,
    pub flags: Option<u16>,
    pub decimals: Option<u8>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MysqlValue {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<BodyCapture>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlTlsRejectedEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub route_name: Option<String>,
    pub listen_addr: String,
    pub client_addr: Option<String>,
    pub client_process: Option<ProcessInfo>,
    pub upstream_addr: String,
    pub capability_flags: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyErrorEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub protocol: String,
    pub client_addr: Option<String>,
    pub client_process: Option<ProcessInfo>,
    pub target: Option<String>,
    pub error: String,
}

impl Recorder {
    pub async fn new(output_dir: impl AsRef<Path>) -> Result<Self> {
        let output_dir = output_dir.as_ref();
        tokio::fs::create_dir_all(output_dir)
            .await
            .with_context(|| format!("failed to create recording dir {}", output_dir.display()))?;
        let path = output_dir.join("traffic.jsonl");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to open JSONL recording file {}", path.display()))?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            output_dir: Arc::new(output_dir.to_path_buf()),
            case_write_lock: Arc::new(Mutex::new(())),
        })
    }

    pub async fn record(&self, event: RecorderEvent) -> Result<()> {
        let mut line = serde_json::to_vec(&event).context("failed to serialize recorder event")?;
        line.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&line)
            .await
            .context("failed to append recorder event")?;
        file.flush()
            .await
            .context("failed to flush recorder event")?;
        Ok(())
    }

    pub async fn write_case_json<T: Serialize>(
        &self,
        case: &CaseContext,
        filename: &str,
        value: &T,
    ) -> Result<()> {
        let path = self.case_dir(case).join(filename);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create case recording dir {}", parent.display())
            })?;
        }
        let mut payload =
            serde_json::to_vec_pretty(value).context("failed to serialize case recording file")?;
        payload.push(b'\n');
        tokio::fs::write(&path, payload)
            .await
            .with_context(|| format!("failed to write case recording file {}", path.display()))
    }

    pub async fn append_case_dependency(
        &self,
        case: &CaseContext,
        event: &RecorderEvent,
        matched_by: &str,
    ) -> Result<()> {
        let _guard = self.case_write_lock.lock().await;
        let dir = self.case_dir(case);
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("failed to create case recording dir {}", dir.display()))?;
        let path = dir.join(case_dependency_filename(event));
        let mut value =
            serde_json::to_value(event).context("failed to serialize case dependency event")?;
        compact_case_dependency_process_info(&mut value);
        if let serde_json::Value::Object(object) = &mut value {
            object.insert(
                "case_dependency_matched_by".to_string(),
                serde_json::Value::String(matched_by.to_string()),
            );
        }
        let mut line =
            serde_json::to_vec(&value).context("failed to serialize case dependency event")?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to open case dependencies file {}", path.display()))?;
        file.write_all(&line)
            .await
            .context("failed to append case dependency event")?;
        file.flush()
            .await
            .context("failed to flush case dependency event")
    }

    fn case_dir(&self, case: &CaseContext) -> std::path::PathBuf {
        self.output_dir
            .join(sanitize_path_component(&case.rule_name))
            .join(case.id.to_string())
    }
}

fn case_dependency_filename(event: &RecorderEvent) -> &'static str {
    if is_case_dependency_debug_event(event) {
        "dependencies-debug.jsonl"
    } else {
        "dependencies.jsonl"
    }
}

fn is_case_dependency_debug_event(event: &RecorderEvent) -> bool {
    matches!(
        event,
        RecorderEvent::MysqlQuery(_)
            | RecorderEvent::MysqlResponse(_)
            | RecorderEvent::MysqlPacket(_)
    )
}

fn compact_case_dependency_process_info(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(process) = object.get_mut("client_process")
                && let Some(pid) = process.get("pid").and_then(serde_json::Value::as_u64)
            {
                *process = serde_json::Value::Number(pid.into());
            }
            for child in object.values_mut() {
                compact_case_dependency_process_info(child);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                compact_case_dependency_process_info(child);
            }
        }
        _ => {}
    }
}

pub fn capture_body(bytes: &[u8], max_body_bytes: usize) -> BodyCapture {
    let stored_len = bytes.len().min(max_body_bytes);
    capture_body_with_original_len(&bytes[..stored_len], bytes.len())
}

pub fn capture_body_with_original_len(bytes: &[u8], original_len: usize) -> BodyCapture {
    BodyCapture {
        encoding: "base64",
        original_len,
        stored_len: bytes.len(),
        truncated: original_len > bytes.len(),
        data: STANDARD.encode(bytes),
    }
}

pub fn capture_case_body(
    bytes: &[u8],
    max_body_bytes: usize,
    headers: Option<&HeaderMap>,
) -> CaseBodyCapture {
    let content_encoding = headers.and_then(content_encoding);
    let (body, decoded, decode_error) = match content_encoding.as_deref() {
        Some(encoding) => match decode_content_encoding(bytes, encoding) {
            Ok(decoded) => (decoded, true, None),
            Err(err) => (bytes.to_vec(), false, Some(err.to_string())),
        },
        None => (bytes.to_vec(), false, None),
    };
    let stored_len = body.len().min(max_body_bytes);
    let stored = &body[..stored_len];
    match std::str::from_utf8(stored) {
        Ok(text) => CaseBodyCapture {
            encoding: "utf8",
            original_len: bytes.len(),
            stored_len,
            truncated: body.len() > max_body_bytes,
            decoded,
            content_encoding,
            data: text.to_string(),
            decode_error,
        },
        Err(_) => CaseBodyCapture {
            encoding: "base64",
            original_len: bytes.len(),
            stored_len,
            truncated: body.len() > max_body_bytes,
            decoded,
            content_encoding,
            data: STANDARD.encode(stored),
            decode_error,
        },
    }
}

pub fn redact_headers(headers: &HeaderMap, sensitive_names: &[String]) -> HeaderMapSnapshot {
    let sensitive = sensitive_names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut out = HeaderMapSnapshot::new();

    for (name, value) in headers {
        let name = name.as_str().to_ascii_lowercase();
        let rendered = if sensitive.contains(&name) {
            "<redacted>".to_string()
        } else {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|_| STANDARD.encode(value.as_bytes()))
        };
        out.entry(name).or_default().push(rendered);
    }

    out
}

fn content_encoding(headers: &HeaderMap) -> Option<String> {
    headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn decode_content_encoding(bytes: &[u8], encoding: &str) -> Result<Vec<u8>> {
    let mut out = bytes.to_vec();
    for coding in encoding
        .split(',')
        .map(str::trim)
        .filter(|coding| !coding.is_empty())
        .rev()
    {
        out = match coding {
            "gzip" | "x-gzip" => {
                let mut decoder = GzDecoder::new(out.as_slice());
                let mut decoded = Vec::new();
                decoder
                    .read_to_end(&mut decoded)
                    .context("failed to decode gzip body")?;
                decoded
            }
            "deflate" => {
                let mut decoder = ZlibDecoder::new(out.as_slice());
                let mut decoded = Vec::new();
                decoder
                    .read_to_end(&mut decoded)
                    .context("failed to decode deflate body")?;
                decoded
            }
            "identity" => out,
            other => anyhow::bail!("unsupported content-encoding {other}"),
        };
    }
    Ok(out)
}

fn sanitize_path_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unnamed".to_string()
    } else {
        sanitized
    }
}

impl From<Bytes> for BodyCapture {
    fn from(value: Bytes) -> Self {
        capture_body(&value, value.len())
    }
}

#[cfg(test)]
mod tests {
    use hyper::header::{AUTHORIZATION, COOKIE, HeaderValue};

    use super::*;

    #[test]
    fn captures_body_with_truncation() {
        let capture = capture_body(b"abcdef", 3);
        assert_eq!(capture.original_len, 6);
        assert_eq!(capture.stored_len, 3);
        assert!(capture.truncated);
        assert_eq!(capture.data, "YWJj");
    }

    #[test]
    fn captures_case_body_with_gzip_decoding() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(br#"{"ok":true}"#).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());

        let capture = capture_case_body(&compressed, 1024, Some(&headers));
        assert_eq!(capture.encoding, "utf8");
        assert!(capture.decoded);
        assert_eq!(capture.data, r#"{"ok":true}"#);
    }

    #[test]
    fn redacts_sensitive_headers_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        headers.insert(COOKIE, HeaderValue::from_static("a=b"));

        let snapshot = redact_headers(&headers, &["authorization".into(), "cookie".into()]);
        assert_eq!(snapshot["authorization"], vec!["<redacted>".to_string()]);
        assert_eq!(snapshot["cookie"], vec!["<redacted>".to_string()]);
    }

    #[tokio::test]
    async fn case_dependency_records_match_reason() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
        };
        let event = RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: "test".to_string(),
            client_addr: None,
            client_process: None,
            target: Some("upstream".to_string()),
            error: "boom".to_string(),
        });

        recorder
            .append_case_dependency(&case, &event, "active_window")
            .await
            .unwrap();

        let raw = tokio::fs::read_to_string(
            temp.path()
                .join("api")
                .join(case.id.to_string())
                .join("dependencies.jsonl"),
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(value["event_type"], "proxy_error");
        assert_eq!(value["case_dependency_matched_by"], "active_window");
    }

    #[tokio::test]
    async fn case_dependency_compacts_client_process_to_pid() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
        };
        let event = RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: "test".to_string(),
            client_addr: None,
            client_process: Some(ProcessInfo {
                pid: 42,
                comm: Some("app".to_string()),
                cmdline: Some("app --serve".to_string()),
                exe: Some("/tmp/app".to_string()),
            }),
            target: Some("upstream".to_string()),
            error: "boom".to_string(),
        });

        recorder
            .append_case_dependency(&case, &event, "process")
            .await
            .unwrap();

        let raw = tokio::fs::read_to_string(
            temp.path()
                .join("api")
                .join(case.id.to_string())
                .join("dependencies.jsonl"),
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(value["client_process"], 42);
        assert_eq!(value["case_dependency_matched_by"], "process");
    }

    #[tokio::test]
    async fn case_dependency_routes_mysql_protocol_details_to_debug_file() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
        };
        let event = RecorderEvent::MysqlQuery(MysqlQueryEvent {
            id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            sequence: 1,
            timestamp: Utc::now(),
            client_addr: Some("127.0.0.1:12345".to_string()),
            client_process: Some(ProcessInfo {
                pid: 42,
                comm: Some("app".to_string()),
                cmdline: Some("app --serve".to_string()),
                exe: Some("/tmp/app".to_string()),
            }),
            command: "COM_QUERY".to_string(),
            query: Some("select 1".to_string()),
            payload_len: 9,
        });

        recorder
            .append_case_dependency(&case, &event, "process")
            .await
            .unwrap();

        let case_dir = temp.path().join("api").join(case.id.to_string());
        assert!(!case_dir.join("dependencies.jsonl").exists());
        let raw = tokio::fs::read_to_string(case_dir.join("dependencies-debug.jsonl"))
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(value["event_type"], "mysql_query");
        assert_eq!(value["client_process"], 42);
        assert_eq!(value["case_dependency_matched_by"], "process");
    }
}
