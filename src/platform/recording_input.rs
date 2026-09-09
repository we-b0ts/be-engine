use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::case_group::resolve_recording_api_case_dirs;
use crate::config::DEFAULT_BODY_LIMIT_BYTES;
use crate::recorded_request::RecordedHttpClient;
use crate::recording_api::RecordingApi;
use crate::recording_control::notify_recording_input_complete;

const MAX_REQUEST_FILES: usize = 1_000;
const REQUEST_INTERVAL: Duration = Duration::from_millis(100);
const MAX_LOGGED_ERRORS: usize = 10;

#[derive(Debug, Clone)]
pub struct ManagedRecordingInputOptions {
    pub case_source: PathBuf,
    pub recording_apis: Vec<RecordingApi>,
    pub origin: String,
    pub motan_upstream: Option<String>,
    pub request_timeout: Duration,
    pub completion: Option<ManagedRecordingInputCompletion>,
}

#[derive(Debug, Clone)]
pub struct ManagedRecordingInputCompletion {
    pub control_socket: PathBuf,
    pub quiet_period: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedRecordingInputResult {
    pub request_templates: usize,
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub input_exhausted: bool,
}

pub async fn drive_managed_recording_input(
    options: ManagedRecordingInputOptions,
) -> Result<ManagedRecordingInputResult> {
    let case_source = std::fs::canonicalize(&options.case_source).with_context(|| {
        format!(
            "failed to resolve managed recording input {}",
            options.case_source.display()
        )
    })?;
    let case_sources = resolve_case_sources(&case_source, &options.recording_apis)?;
    let requests = discover_requests(&case_sources)?;
    ensure!(
        !requests.is_empty(),
        "managed recording input contains no request.json files"
    );
    let mut client = RecordedHttpClient::new_recording_input(
        options.origin,
        options.request_timeout,
        DEFAULT_BODY_LIMIT_BYTES,
    );
    // A finite comparison sends one transformed request to the gateway, which
    // forwards those identical bytes to both source and candidate.
    if let Some(root) = case_source
        .ancestors()
        .find(|p| p.file_name().is_some_and(|n| n == ".traffic-e2e"))
        .and_then(Path::parent)
    {
        let (_, config) = crate::e2e_run::resolve_project(root)?;
        client = client.with_request_rules(root, &config.replay_policy)?;
    }
    let mut attempted = 0_usize;
    let mut succeeded = 0_usize;
    let mut failed = 0_usize;
    let mut logged_errors = 0_usize;
    let request_templates = requests.len();
    let mut pending = VecDeque::from(requests);
    let shutdown = super::shutdown_signal();
    tokio::pin!(shutdown);
    let mut input_exhausted = false;
    loop {
        let Some(request_path) = pending.pop_front() else {
            input_exhausted = true;
            if let Some(completion) = &options.completion {
                info!(
                    quiet_period_ms = completion.quiet_period.as_millis(),
                    "managed recording input exhausted; waiting before completion"
                );
                tokio::select! {
                    signal = &mut shutdown => {
                        signal?;
                        input_exhausted = false;
                        break;
                    }
                    () = tokio::time::sleep(completion.quiet_period) => {}
                }
                tokio::select! {
                    signal = &mut shutdown => {
                        signal?;
                        input_exhausted = false;
                    }
                    result = notify_recording_input_complete(&completion.control_socket, succeeded) => {
                        result?;
                    }
                }
            }
            break;
        };
        attempted = attempted.saturating_add(1);
        let response = tokio::select! {
            signal = &mut shutdown => {
                signal?;
                break;
            }
            response = send_request(
                &client,
                options.motan_upstream.as_deref(),
                &request_path,
                options.request_timeout,
            ) => response,
        };
        match response {
            Ok(_) => succeeded = succeeded.saturating_add(1),
            Err(error) => {
                failed = failed.saturating_add(1);
                pending.push_back(request_path);
                if logged_errors < MAX_LOGGED_ERRORS {
                    warn!(%error, "managed recording request input failed");
                    logged_errors += 1;
                }
            }
        }
        if pending.is_empty() {
            continue;
        }
        tokio::select! {
            signal = &mut shutdown => {
                signal?;
                break;
            }
            () = tokio::time::sleep(REQUEST_INTERVAL) => {}
        }
    }
    ensure!(
        succeeded > 0,
        "managed recording input did not deliver any request successfully"
    );
    info!(
        attempted,
        succeeded, failed, input_exhausted, "managed recording input stopped"
    );
    Ok(ManagedRecordingInputResult {
        request_templates,
        attempted,
        succeeded,
        failed,
        input_exhausted,
    })
}

#[derive(Deserialize)]
struct RequestKind {
    #[serde(default)]
    protocol_version: Option<String>,
    #[serde(default)]
    frame: Option<RecordedFrame>,
}

#[derive(Deserialize)]
struct RecordedFrame {
    encoding: String,
    data: String,
    truncated: bool,
}

async fn send_request(
    http: &RecordedHttpClient,
    motan_upstream: Option<&str>,
    request_path: &Path,
    timeout: Duration,
) -> Result<()> {
    let bytes = tokio::fs::read(request_path)
        .await
        .with_context(|| format!("failed to read request template {}", request_path.display()))?;
    let kind: RequestKind = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid request template {}", request_path.display()))?;
    if kind.protocol_version.is_none() {
        http.send(request_path).await?;
        return Ok(());
    }
    let upstream = motan_upstream.context(
        "managed recording input contains Motan requests but no Motan gateway endpoint was provided",
    )?;
    let frame = kind.frame.context("Motan request template has no frame")?;
    ensure!(
        !frame.truncated,
        "Motan request template frame is truncated"
    );
    let raw = match frame.encoding.as_str() {
        "utf8" => frame.data.into_bytes(),
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(frame.data)
            .context("Motan request template contains invalid base64")?,
        encoding => anyhow::bail!("unsupported Motan request frame encoding {encoding:?}"),
    };
    let limits = motan_protocol::Limits::default();
    let motan_protocol::DecodeStatus::Complete(request) =
        motan_protocol::decode_frame(&raw, limits)?
    else {
        anyhow::bail!("Motan request template contains an incomplete frame");
    };
    ensure!(
        request.kind == motan_protocol::MessageKind::Request,
        "Motan request template contains a response frame"
    );
    let operation = async {
        let mut stream = TcpStream::connect(upstream)
            .await
            .with_context(|| format!("failed to connect to Motan gateway {upstream}"))?;
        stream
            .write_all(&raw)
            .await
            .context("failed to write Motan request")?;
        if !request.flags.oneway() {
            let mut decoder = motan_protocol::FrameDecoder::new(limits)?;
            loop {
                if let Some(response) = decoder.decode()? {
                    ensure!(
                        response.kind == motan_protocol::MessageKind::Response,
                        "Motan gateway returned a request frame"
                    );
                    ensure!(
                        response.version == request.version,
                        "Motan gateway response protocol version does not match the request"
                    );
                    ensure!(
                        response.request_id == request.request_id,
                        "Motan gateway response request id does not match the request"
                    );
                    break;
                }
                let read = stream.read_buf(decoder.buffer_mut()).await?;
                ensure!(read > 0, "Motan gateway closed before returning a response");
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout(timeout, operation)
        .await
        .context("managed Motan request timed out")??;
    Ok(())
}

fn resolve_case_sources(
    case_source: &Path,
    recording_apis: &[RecordingApi],
) -> Result<Vec<PathBuf>> {
    if recording_apis.is_empty() {
        return Ok(vec![case_source.to_path_buf()]);
    }
    let sources = recording_apis
        .iter()
        .map(|api| resolve_recording_api_case_dirs(case_source, api))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>();
    sources
        .into_iter()
        .map(|path| {
            let metadata = std::fs::symlink_metadata(&path).with_context(|| {
                format!(
                    "managed recording API case directory is missing: {}",
                    path.display()
                )
            })?;
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "managed recording API case source must be a directory without symlinks: {}",
                path.display()
            );
            Ok(path)
        })
        .collect()
}

fn discover_requests(case_sources: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut pending = case_sources.to_vec();
    let mut requests = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)
            .with_context(|| format!("failed to read case directory {}", directory.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "managed recording input must not contain symlinks: {}",
                path.display()
            );
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && path.file_name().is_some_and(|name| name == "request.json")
            {
                requests.push(path);
                ensure!(
                    requests.len() <= MAX_REQUEST_FILES,
                    "managed recording input exceeds {MAX_REQUEST_FILES} request templates"
                );
            }
        }
    }
    requests.sort();
    Ok(requests)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::recording_control::{RecordingControlServer, RecordingLifecycle, RecordingListener};

    #[test]
    fn discovers_requests_in_stable_order_and_rejects_unbounded_inputs() {
        let root = tempfile::tempdir().unwrap();
        for name in ["case-b", "case-a"] {
            let case = root.path().join(name);
            std::fs::create_dir_all(&case).unwrap();
            std::fs::write(case.join("request.json"), b"{}").unwrap();
            std::fs::write(case.join("expected-response.json"), b"{}").unwrap();
        }

        let requests = discover_requests(&[root.path().to_path_buf()]).unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0] < requests[1]);
    }

    #[test]
    fn selected_recording_api_uses_only_its_case_directory() {
        let root = tempfile::tempdir().unwrap();
        for (directory, cases) in [("api-a", 2), ("api-b", 1)] {
            for index in 0..cases {
                let case = root
                    .path()
                    .join("apis")
                    .join(directory)
                    .join(format!("case-{directory}-{index}"));
                std::fs::create_dir_all(&case).unwrap();
                let api_name = &directory[4..];
                std::fs::write(
                    case.join("request.json"),
                    format!(
                        r#"{{"method":"POST","uri":"/api/{api_name}","api_pattern":"/api/{api_name}"}}"#
                    ),
                )
                .unwrap();
                std::fs::write(case.join("expected-response.json"), b"{}").unwrap();
            }
        }
        let api = "POST /api/b".parse::<RecordingApi>().unwrap();

        let sources = resolve_case_sources(root.path(), &[api]).unwrap();
        let requests = discover_requests(&sources).unwrap();

        assert_eq!(sources, [root.path().join("apis/api-b/case-api-b-0")]);
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with(&sources[0]));
    }

    #[tokio::test]
    async fn wildcard_input_sends_cases_from_multiple_members_once_and_excludes_other_apis() {
        let root = tempfile::tempdir().unwrap();
        for (member, id, method, uri) in [
            (
                "api-teams-110467-skills",
                "first",
                "GET",
                "/api/teams/110467/skills",
            ),
            (
                "api-teams-265320-skills",
                "second",
                "GET",
                "/api/teams/265320/skills",
            ),
            (
                "api-teams-110467-skills",
                "other-method",
                "POST",
                "/api/teams/110467/skills",
            ),
            (
                "api-teams-110467-skills",
                "other-path",
                "GET",
                "/api/teams/110467/members",
            ),
        ] {
            let case = root.path().join("apis").join(member).join(id);
            std::fs::create_dir_all(&case).unwrap();
            std::fs::write(
                case.join("request.json"),
                serde_json::to_vec(&serde_json::json!({
                    "method": method, "uri": uri, "api_pattern": uri, "headers": {},
                    "body": {"encoding": "utf8", "data": "", "truncated": false}
                }))
                .unwrap(),
            )
            .unwrap();
            std::fs::write(case.join("expected-response.json"), b"{}").unwrap();
        }
        let apis = ["GET /api/teams/*/skills", "GET /api/teams/110467/skills"]
            .map(|api| api.parse::<RecordingApi>().unwrap());
        let sources = resolve_case_sources(root.path(), &apis).unwrap();
        assert_eq!(sources.len(), 2);
        assert!(sources[0].ends_with("api-teams-110467-skills/first"));
        assert!(sources[1].ends_with("api-teams-265320-skills/second"));
        let missing = "GET /api/missing".parse().unwrap();
        assert!(resolve_case_sources(root.path(), &[missing]).is_err());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let upstream = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut bytes = [0; 1024];
                    let read = stream.read(&mut bytes).await.unwrap();
                    assert_ne!(read, 0);
                    request.extend_from_slice(&bytes[..read]);
                    if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        break;
                    }
                }
                received.push(
                    String::from_utf8(request)
                        .unwrap()
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned(),
                );
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    )
                    .await
                    .unwrap();
            }
            received
        });
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            drive_managed_recording_input(ManagedRecordingInputOptions {
                case_source: root.path().to_path_buf(),
                recording_apis: apis.to_vec(),
                origin,
                motan_upstream: None,
                request_timeout: Duration::from_secs(1),
                completion: None,
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.request_templates, 2);
        assert_eq!(result.attempted, 2);
        assert_eq!(result.succeeded, 2);
        assert_eq!(result.failed, 0);
        assert!(result.input_exhausted);
        assert_eq!(
            upstream.await.unwrap(),
            [
                "GET /api/teams/110467/skills HTTP/1.1",
                "GET /api/teams/265320/skills HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn exhausted_input_waits_for_the_final_quiet_period_then_notifies_comparison() {
        let root = tempfile::tempdir().unwrap();
        let case = root.path().join("case");
        std::fs::create_dir_all(&case).unwrap();
        std::fs::write(
            case.join("request.json"),
            br#"{
                "method":"POST",
                "uri":"/api/config",
                "headers":{},
                "body":{"encoding":"utf8","data":"{}","truncated":false}
            }"#,
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .unwrap();
        });

        let control_socket = root.path().join("comparison.sock");
        let lifecycle = RecordingLifecycle::for_comparison_gateway(true, false, false);
        lifecycle.mark_listener_ready(RecordingListener::HttpGateway);
        let (control, mut completion) =
            RecordingControlServer::start_for_comparison(lifecycle, control_socket.clone())
                .await
                .unwrap();
        let quiet_period = Duration::from_millis(30);
        let started = Instant::now();

        let result = drive_managed_recording_input(ManagedRecordingInputOptions {
            case_source: root.path().to_path_buf(),
            recording_apis: Vec::new(),
            origin,
            motan_upstream: None,
            request_timeout: Duration::from_secs(1),
            completion: Some(ManagedRecordingInputCompletion {
                control_socket,
                quiet_period,
            }),
        })
        .await
        .unwrap();

        assert!(result.input_exhausted);
        assert_eq!(result.request_templates, 1);
        assert_eq!(result.succeeded, 1);
        assert!(started.elapsed() >= quiet_period);
        completion.changed().await.unwrap();
        assert_eq!(completion.borrow().unwrap().delivered, 1);
        upstream.await.unwrap();
        control.shutdown().await.unwrap();
    }
}
