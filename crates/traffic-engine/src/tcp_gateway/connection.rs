use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use tokio::io;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{Duration, sleep, timeout};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::AppState;
use crate::access_policy::{AccessDecision, OperationClass};
use crate::dns_mock::FakeDnsEntry;
use crate::recording_control::RecordingListener;

use super::{
    RawTcpOptions, TcpConnectionRecord, detection::DetectedProtocol, detection::Detection,
    detection::detect_client_protocol_with, detection::detect_server_protocol_with,
    detection::protocol_override, record_proxy_error, record_tcp_connection, serve_http_connection,
    serve_https_mitm_connection,
};

const SO_ORIGINAL_DST: libc::c_int = 80;
const INITIAL_PEEK_TIMEOUT: Duration = Duration::from_millis(100);
const PARTIAL_PEEK_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_SNIFF_BYTES: usize = 4096;

pub(crate) async fn run(state: AppState) -> Result<()> {
    let config = state.config().tcp_gateway.clone();
    let listener = bind_listener(config.listen, config.backlog)?;
    state.mark_recording_listener_ready(RecordingListener::TcpGateway);
    info!(
        listen = %config.listen,
        backlog = config.backlog,
        "TCP fake-IP gateway listening"
    );

    loop {
        let (client, peer_addr) = listener
            .accept()
            .await
            .context("failed to accept TCP gateway client")?;
        client
            .set_nodelay(true)
            .context("failed to enable TCP_NODELAY for TCP gateway client")?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(client, peer_addr, state).await {
                if is_expected_connection_end(&err) {
                    debug!(error = %format!("{err:#}"), "TCP gateway connection ended");
                } else {
                    warn!(error = %format!("{err:#}"), "TCP gateway connection failed");
                }
            }
        });
    }
}

fn bind_listener(listen: SocketAddr, backlog: u32) -> Result<TcpListener> {
    let socket = if listen.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .with_context(|| format!("failed to create TCP gateway socket for {listen}"))?;
    #[cfg(not(windows))]
    socket
        .set_reuseaddr(true)
        .with_context(|| format!("failed to set SO_REUSEADDR for TCP gateway {listen}"))?;
    socket
        .bind(listen)
        .with_context(|| format!("failed to bind TCP gateway {listen}"))?;
    socket
        .listen(backlog)
        .with_context(|| format!("failed to listen on TCP gateway {listen} with backlog {backlog}"))
}

fn is_expected_connection_end(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            )
        })
    })
}

pub(crate) async fn handle_connection(
    client: TcpStream,
    peer_addr: SocketAddr,
    state: AppState,
) -> Result<()> {
    let fake_addr = original_dst(&client).or_else(|err| {
        warn!(error = %err, "SO_ORIGINAL_DST unavailable; falling back to local_addr");
        client.local_addr().context("failed to read local_addr")
    })?;
    let client_addr = Some(peer_addr.to_string());
    let IpAddr::V4(fake_ip) = fake_addr.ip() else {
        return Err(anyhow!("TCP gateway only supports IPv4 fake IPs"));
    };
    let entry = match state.dns_registry().get_by_fake_ip(fake_ip).await {
        Some(entry) => entry,
        None if state.has_redis_snapshot_port(fake_addr.port()) => {
            direct_cache_snapshot_entry(fake_ip)
        }
        None => {
            let error = format!(
                "no DNS mock mapping for fake IP {fake_ip}; likely stale client DNS cache, recorder restart without persisted mapping, or traffic not produced by this DNS mock"
            );
            record_proxy_error(
                &state,
                "tcp_gateway",
                client_addr.clone(),
                Some(fake_addr.to_string()),
                error.clone(),
            )
            .await;
            return Err(anyhow!(error));
        }
    };
    state
        .recorder()
        .observe_accessed_endpoint(&entry.domain, fake_addr.port())
        .await?;

    if let Err(error) = state.recording_upstream(&entry.domain, fake_addr.port()) {
        record_proxy_error(
            &state,
            "tcp_gateway",
            client_addr,
            Some(format!("{}:{}", entry.domain, fake_addr.port())),
            error.to_string(),
        )
        .await;
        return Err(error);
    }

    if state.dns_bypass_matcher().matches(&entry.domain) {
        return proxy_raw_tcp(
            client,
            fake_addr,
            entry,
            client_addr,
            state,
            RawTcpOptions {
                record_connection: false,
                sniff_server_first_protocols: false,
                detected_protocol: Some(DetectedProtocol::Raw),
            },
        )
        .await;
    }

    let config = state.config().tcp_gateway.clone();
    let override_protocol =
        protocol_override(&config.protocol_detection, &entry.domain, fake_addr.port());
    let detection = if let Some(protocol) = override_protocol {
        Detection::Match(protocol)
    } else if config.protocol_detection.enabled || config.record_http {
        peek_client_protocol(&client, state.dependency_providers())
            .await
            .unwrap_or(Detection::NeedMore)
    } else {
        Detection::NoMatch
    };

    if config.record_http && detection == Detection::Match(DetectedProtocol::Http) {
        return serve_http_connection(client, fake_addr, entry, client_addr, state).await;
    }
    if detection == Detection::Match(DetectedProtocol::Tls)
        && let Some(protocol) = plaintext_protocol_port_hint(&state, fake_addr.port())
    {
        reject_protocol_tls_if_needed(
            &client,
            &state,
            &entry.domain,
            fake_addr,
            client_addr.clone(),
            protocol,
        )
        .await?;
    }
    if config.record_http
        && config.mitm_https
        && detection == Detection::Match(DetectedProtocol::Tls)
        && (config.https_ports.is_empty() || config.https_ports.contains(&fake_addr.port()))
    {
        return serve_https_mitm_connection(client, fake_addr, entry, client_addr, state).await;
    }

    proxy_raw_tcp(
        client,
        fake_addr,
        entry,
        client_addr,
        state,
        RawTcpOptions {
            record_connection: true,
            sniff_server_first_protocols: matches!(detection, Detection::NeedMore),
            detected_protocol: match detection {
                Detection::Match(protocol) => Some(protocol),
                Detection::NeedMore => None,
                Detection::NoMatch => Some(DetectedProtocol::Raw),
            },
        },
    )
    .await
}

fn direct_cache_snapshot_entry(ip: Ipv4Addr) -> FakeDnsEntry {
    let now = Utc::now();
    FakeDnsEntry {
        domain: ip.to_string(),
        fake_ip: ip,
        real_ips: vec![ip],
        response_alias: false,
        upstream_authority: None,
        upstream_protocol: None,
        first_seen: now,
        last_seen: now,
    }
}

#[allow(clippy::too_many_arguments)]
async fn proxy_raw_tcp(
    mut client: TcpStream,
    fake_addr: SocketAddr,
    entry: FakeDnsEntry,
    client_addr: Option<String>,
    state: AppState,
    options: RawTcpOptions,
) -> Result<()> {
    let id = Uuid::new_v4();
    let started = Instant::now();
    let upstream_addr = routed_upstream_addr(&state, &entry, fake_addr.port())?;
    let mut upstream = if options.record_connection {
        let protocol = match options
            .detected_protocol
            .or_else(|| protocol_hint(&state, fake_addr.port()))
        {
            Some(DetectedProtocol::Redis) => "redis",
            Some(DetectedProtocol::Registered(protocol)) => protocol.as_str(),
            _ => "tcp",
        };
        match crate::recorder::connect_failure::connect_upstream(
            &state,
            &client,
            protocol,
            (&entry.domain, fake_addr.port()),
            upstream_addr,
        )
        .await
        .with_context(|| format!("failed to connect upstream {upstream_addr}"))?
        {
            Some(stream) => stream,
            None => return Ok(()),
        }
    } else {
        tokio::select! {
            upstream = TcpStream::connect(upstream_addr) => upstream?,
            _ = state.inner.active_cases.wait_for_quiescing() => return Ok(()),
        }
    };

    upstream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY for TCP gateway upstream")?;

    let mut protocol = options.detected_protocol;
    if protocol.is_none()
        && options.sniff_server_first_protocols
        && let Detection::Match(server) =
            peek_server_protocol(&upstream, state.dependency_providers()).await?
    {
        protocol = Some(server);
    }
    if protocol.is_none() && state.config().tcp_gateway.protocol_detection.enabled {
        let hint = protocol_hint(&state, fake_addr.port());
        protocol = if options.sniff_server_first_protocols && hint.is_none() {
            Some(
                detect_protocol_when_data_arrives(&client, &upstream, state.dependency_providers())
                    .await?,
            )
        } else {
            match peek_client_protocol_with_timeout(
                &client,
                PARTIAL_PEEK_TIMEOUT,
                state.dependency_providers(),
            )
            .await?
            {
                Detection::Match(protocol) => Some(protocol),
                Detection::NeedMore | Detection::NoMatch => hint,
            }
        };
    }
    match protocol.unwrap_or(DetectedProtocol::Raw) {
        DetectedProtocol::Registered(protocol) => {
            let info = traffic_protocol::connection::ConnectionInfo {
                endpoint: traffic_protocol::connection::Endpoint {
                    host: entry.domain,
                    port: fake_addr.port(),
                },
                client_addr,
                upstream_addr: Some(upstream_addr.to_string()),
                max_frame_bytes: state.config().recording.max_body_bytes,
            };
            crate::recorder::native::handle_connected(protocol, client, upstream, state, info).await
        }
        DetectedProtocol::Redis => {
            reject_protocol_tls_if_needed(
                &client,
                &state,
                &entry.domain,
                fake_addr,
                client_addr.clone(),
                "redis",
            )
            .await?;
            let info = traffic_protocol::connection::ConnectionInfo {
                endpoint: traffic_protocol::connection::Endpoint {
                    host: entry.domain,
                    port: fake_addr.port(),
                },
                client_addr,
                upstream_addr: Some(upstream_addr.to_string()),
                max_frame_bytes: state.config().recording.max_body_bytes,
            };
            crate::recorder::native::handle_connected(
                crate::protocols::DependencyProtocol::Redis,
                client,
                upstream,
                state,
                info,
            )
            .await
        }
        DetectedProtocol::Tls
            if state.config().tcp_gateway.record_http
                && state.config().tcp_gateway.mitm_https
                && (state.config().tcp_gateway.https_ports.is_empty()
                    || state
                        .config()
                        .tcp_gateway
                        .https_ports
                        .contains(&fake_addr.port())) =>
        {
            drop(upstream);
            serve_https_mitm_connection(client, fake_addr, entry, client_addr, state).await
        }
        DetectedProtocol::Tls => Err(anyhow!(
            "TLS-looking connection was not eligible for HTTPS MITM on port {}",
            fake_addr.port()
        )),
        DetectedProtocol::Http if state.config().tcp_gateway.record_http => {
            drop(upstream);
            serve_http_connection(client, fake_addr, entry, client_addr, state).await
        }
        DetectedProtocol::Http | DetectedProtocol::Raw => {
            let targets = state.capture_dependency_start(
                crate::dependency::observation::ProtocolRef::observation(
                    id,
                    "tcp_gateway_connection",
                ),
            );
            let _connection = state
                .dependency_connections()
                .register("raw_tcp", &[&client, &upstream])?;
            let operation_class = OperationClass::Unknown;
            if state.access_decision(operation_class) == AccessDecision::Reject {
                state
                    .record_readonly_rejection(
                        "raw_tcp",
                        operation_class,
                        "raw_stream",
                        client_addr.clone(),
                        Some(format!("{}:{}", entry.domain, fake_addr.port())),
                        "unstructured TCP traffic is not allowed by the recording access policy",
                    )
                    .await;
                return Ok(());
            }
            let (client_to_server, server_to_client) =
                io::copy_bidirectional(&mut client, &mut upstream)
                    .await
                    .context("failed to proxy TCP gateway stream")?;
            if options.record_connection {
                record_tcp_connection(
                    &state,
                    TcpConnectionRecord {
                        id,
                        client_addr,
                        domain: Some(entry.domain),
                        fake_addr,
                        upstream_addr: Some(upstream_addr),
                        client_to_server_bytes: client_to_server,
                        server_to_client_bytes: server_to_client,
                        duration_ms: started.elapsed().as_millis(),
                        error: None,
                    },
                    targets,
                )
                .await;
            }
            Ok(())
        }
    }
}

async fn reject_protocol_tls_if_needed(
    client: &TcpStream,
    state: &AppState,
    domain: &str,
    fake_addr: SocketAddr,
    client_addr: Option<String>,
    protocol: &str,
) -> Result<()> {
    let mut prefix = [0_u8; 3];
    let len = timeout(INITIAL_PEEK_TIMEOUT, client.peek(&mut prefix))
        .await
        .ok()
        .transpose()?
        .unwrap_or(0);
    if len >= 3 && prefix[0] == 0x16 && prefix[1] == 0x03 && prefix[2] <= 0x04 {
        let error = format!("{protocol} TLS is unsupported for recording");
        record_proxy_error(
            state,
            protocol,
            client_addr,
            Some(format!("{domain}:{}", fake_addr.port())),
            error.clone(),
        )
        .await;
        return Err(anyhow!(error));
    }
    Ok(())
}

fn protocol_hint(state: &AppState, port: u16) -> Option<DetectedProtocol> {
    let detection = &state.config().tcp_gateway.protocol_detection;
    if detection.redis_port_hints.contains(&port) {
        Some(DetectedProtocol::Redis)
    } else {
        None
    }
}

fn plaintext_protocol_port_hint(state: &AppState, port: u16) -> Option<&'static str> {
    let detection = &state.config().tcp_gateway.protocol_detection;
    if !detection.enabled {
        return None;
    }
    if detection.redis_port_hints.contains(&port) {
        Some("redis")
    } else {
        None
    }
}

async fn peek_client_protocol(
    stream: &TcpStream,
    providers: &crate::protocols::DependencyProviders,
) -> Result<Detection> {
    peek_client_protocol_with_timeout(stream, INITIAL_PEEK_TIMEOUT, providers).await
}

async fn detect_protocol_when_data_arrives(
    client: &TcpStream,
    upstream: &TcpStream,
    providers: &crate::protocols::DependencyProviders,
) -> Result<DetectedProtocol> {
    tokio::select! {
        detection = peek_client_protocol_after_data(client, providers) => {
            Ok(match detection? {
                Detection::Match(protocol) => protocol,
                Detection::NeedMore | Detection::NoMatch => DetectedProtocol::Raw,
            })
        }
        server = peek_server_protocol_after_data(upstream, providers) => {
            Ok(match server? {
                Detection::Match(protocol) => protocol,
                Detection::NeedMore | Detection::NoMatch => DetectedProtocol::Raw,
            })
        }
    }
}

async fn peek_client_protocol_after_data(
    stream: &TcpStream,
    providers: &crate::protocols::DependencyProviders,
) -> Result<Detection> {
    let mut first = [0_u8; 1];
    if stream.peek(&mut first).await? == 0 {
        return Ok(Detection::NoMatch);
    }
    peek_client_protocol_with_timeout(stream, PARTIAL_PEEK_TIMEOUT, providers).await
}

async fn peek_client_protocol_with_timeout(
    stream: &TcpStream,
    wait: Duration,
    providers: &crate::protocols::DependencyProviders,
) -> Result<Detection> {
    let mut buf = vec![0_u8; MAX_SNIFF_BYTES];
    let len = match timeout(wait, stream.peek(&mut buf)).await {
        Ok(result) => result?,
        Err(_) => return Ok(Detection::NeedMore),
    };
    let mut detection = detect_client_protocol_with(&buf[..len], providers);
    if detection == Detection::NeedMore && len > 0 && len < MAX_SNIFF_BYTES {
        let deadline = tokio::time::Instant::now() + PARTIAL_PEEK_TIMEOUT;
        let mut observed_len = len;
        while detection == Detection::NeedMore
            && observed_len < MAX_SNIFF_BYTES
            && tokio::time::Instant::now() < deadline
        {
            sleep(Duration::from_millis(5)).await;
            let len = stream.peek(&mut buf).await?;
            if len == observed_len {
                continue;
            }
            observed_len = len;
            detection = detect_client_protocol_with(&buf[..len], providers);
        }
    }
    Ok(detection)
}

async fn peek_server_protocol(
    stream: &TcpStream,
    providers: &crate::protocols::DependencyProviders,
) -> Result<Detection> {
    let mut buf = vec![0_u8; MAX_SNIFF_BYTES];
    let mut len = match timeout(INITIAL_PEEK_TIMEOUT, stream.peek(&mut buf)).await {
        Ok(result) => result?,
        Err(_) => return Ok(Detection::NeedMore),
    };
    let deadline = tokio::time::Instant::now() + PARTIAL_PEEK_TIMEOUT;
    let mut detection = detect_server_protocol_with(&buf[..len], providers);
    while detection == Detection::NeedMore
        && len > 0
        && len < buf.len()
        && tokio::time::Instant::now() < deadline
    {
        sleep(Duration::from_millis(5)).await;
        len = stream.peek(&mut buf).await?;
        detection = detect_server_protocol_with(&buf[..len], providers);
    }
    Ok(detection)
}

async fn peek_server_protocol_after_data(
    stream: &TcpStream,
    providers: &crate::protocols::DependencyProviders,
) -> Result<Detection> {
    let mut first = [0_u8; 1];
    if stream.peek(&mut first).await? == 0 {
        return Ok(Detection::NoMatch);
    }
    peek_server_protocol(stream, providers).await
}

pub(super) fn routed_upstream_addr(
    state: &AppState,
    entry: &FakeDnsEntry,
    port: u16,
) -> Result<SocketAddr> {
    if let Some(address) = state.recording_upstream(&entry.domain, port)? {
        return Ok(address);
    }
    upstream_addr(entry, port)
}

fn upstream_addr(entry: &FakeDnsEntry, port: u16) -> Result<SocketAddr> {
    let ip = entry
        .real_ips
        .first()
        .copied()
        .ok_or_else(|| anyhow!("DNS mock entry has no real IPs for {}", entry.domain))?;
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

fn original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("getsockopt SO_ORIGINAL_DST failed");
    }
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

#[cfg(test)]
#[path = "connection_tests.rs"]
mod tests;
