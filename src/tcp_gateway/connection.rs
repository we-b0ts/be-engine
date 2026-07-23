use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use tokio::io;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{Duration, sleep, timeout};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::AppState;
use crate::access_policy::{AccessDecision, OperationClass};
use crate::dns_mock::FakeDnsEntry;
use crate::memcached::MemcachedWireProtocol;
use crate::process_lookup::lookup_tcp_process;
use crate::recorder::ProcessInfo;
use crate::recorder::kafka::{KafkaConnectionContext, handle_connected as handle_connected_kafka};
use crate::recorder::memcached::{
    ConnectionContext as MemcachedConnectionContext, handle_connected as handle_connected_memcached,
};
use crate::recorder::motan::{
    ConnectionContext as MotanConnectionContext, handle_connected as handle_connected_motan,
};
use crate::recorder::mysql::{MysqlConnectionContext, handle_connected_mysql};
use crate::recorder::redis::{
    ConnectionContext as RedisConnectionContext, handle_connected as handle_connected_redis,
};

use super::{
    RawTcpOptions, TcpConnectionRecord, detection::DetectedProtocol, detection::Detection,
    detection::detect_client_protocol, detection::detect_mysql_server,
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

async fn handle_connection(
    client: TcpStream,
    peer_addr: SocketAddr,
    state: AppState,
) -> Result<()> {
    let fake_addr = original_dst(&client).or_else(|err| {
        warn!(error = %err, "SO_ORIGINAL_DST unavailable; falling back to local_addr");
        client.local_addr().context("failed to read local_addr")
    })?;
    let client_addr = Some(peer_addr.to_string());
    let mut process_remote_candidates = vec![fake_addr];
    if let Ok(gateway_addr) = client.local_addr() {
        process_remote_candidates.push(gateway_addr);
    }
    let client_process = lookup_tcp_process(peer_addr, &process_remote_candidates);

    let IpAddr::V4(fake_ip) = fake_addr.ip() else {
        return Err(anyhow!("TCP gateway only supports IPv4 fake IPs"));
    };
    let Some(entry) = state.dns_registry().get_by_fake_ip(fake_ip).await else {
        let error = format!(
            "no DNS mock mapping for fake IP {fake_ip}; likely stale client DNS cache, recorder restart without persisted mapping, or traffic not produced by this DNS mock"
        );
        record_proxy_error(
            &state,
            "tcp_gateway",
            client_addr.clone(),
            client_process.clone(),
            Some(fake_addr.to_string()),
            error.clone(),
        )
        .await;
        return Err(anyhow!(error));
    };

    if state.dns_bypass_matcher().matches(&entry.domain) {
        return proxy_raw_tcp(
            client,
            fake_addr,
            entry,
            client_addr,
            client_process,
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
    } else if config.protocol_detection.enabled
        && config
            .protocol_detection
            .kafka_port_hints
            .contains(&fake_addr.port())
    {
        Detection::Match(DetectedProtocol::Kafka)
    } else if config.protocol_detection.enabled || config.record_http {
        peek_client_protocol(&client)
            .await
            .unwrap_or(Detection::NeedMore)
    } else {
        Detection::NoMatch
    };

    if config.record_http && detection == Detection::Match(DetectedProtocol::Http) {
        return serve_http_connection(client, fake_addr, entry, client_addr, client_process, state)
            .await;
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
            client_process.clone(),
            protocol,
        )
        .await?;
    }
    if config.record_http
        && config.mitm_https
        && detection == Detection::Match(DetectedProtocol::Tls)
        && (config.https_ports.is_empty() || config.https_ports.contains(&fake_addr.port()))
    {
        return serve_https_mitm_connection(
            client,
            fake_addr,
            entry,
            client_addr,
            client_process,
            state,
        )
        .await;
    }

    proxy_raw_tcp(
        client,
        fake_addr,
        entry,
        client_addr,
        client_process,
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

#[allow(clippy::too_many_arguments)]
async fn proxy_raw_tcp(
    mut client: TcpStream,
    fake_addr: SocketAddr,
    entry: FakeDnsEntry,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
    state: AppState,
    options: RawTcpOptions,
) -> Result<()> {
    let id = Uuid::new_v4();
    let started = Instant::now();
    let upstream_addr = upstream_addr(&entry, fake_addr.port())?;
    let mut upstream = match TcpStream::connect(upstream_addr).await {
        Ok(upstream) => upstream,
        Err(err) => {
            if options.record_connection {
                record_tcp_connection(
                    &state,
                    TcpConnectionRecord {
                        id,
                        client_addr: client_addr.clone(),
                        client_process: client_process.clone(),
                        domain: Some(entry.domain.clone()),
                        fake_addr,
                        upstream_addr: Some(upstream_addr),
                        client_to_server_bytes: 0,
                        server_to_client_bytes: 0,
                        duration_ms: started.elapsed().as_millis(),
                        error: Some(err.to_string()),
                    },
                )
                .await;
            }
            return Err(err).with_context(|| format!("failed to connect upstream {upstream_addr}"));
        }
    };

    let mut protocol = options.detected_protocol;
    if protocol.is_none()
        && options.sniff_server_first_protocols
        && upstream_looks_like_mysql(&upstream).await.unwrap_or(false)
    {
        protocol = Some(DetectedProtocol::Mysql);
    }
    if protocol.is_none() && state.config().tcp_gateway.protocol_detection.enabled {
        protocol = match peek_client_protocol_with_timeout(&client, PARTIAL_PEEK_TIMEOUT).await {
            Ok(Detection::Match(protocol)) => Some(protocol),
            _ => protocol_hint(&state, fake_addr.port()),
        };
    }
    if protocol == Some(DetectedProtocol::MemcachedText) {
        let mut first = [0_u8; 1];
        if client.peek(&mut first).await? > 0 && first[0] == 0x80 {
            protocol = Some(DetectedProtocol::MemcachedBinary);
        }
    }

    match protocol.unwrap_or(DetectedProtocol::Raw) {
        DetectedProtocol::Mysql => {
            let context = MysqlConnectionContext {
                route_name: Some(format!("fake-ip:{}", entry.domain)),
                listen_addr: state.config().tcp_gateway.listen.to_string(),
                client_addr,
                client_process,
                target_host: Some(entry.domain.clone()),
                target_port: Some(fake_addr.port()),
                target_addr: Some(super::format_authority(
                    &entry.domain,
                    fake_addr.port(),
                    3306,
                )),
                upstream_addr: upstream_addr.to_string(),
            };
            handle_connected_mysql(client, upstream, state, context).await
        }
        DetectedProtocol::Redis => {
            reject_protocol_tls_if_needed(
                &client,
                &state,
                &entry.domain,
                fake_addr,
                client_addr.clone(),
                client_process.clone(),
                "redis",
            )
            .await?;
            handle_connected_redis(
                client,
                upstream,
                state,
                redis_context(
                    &entry,
                    fake_addr,
                    upstream_addr,
                    client_addr,
                    client_process,
                ),
            )
            .await
        }
        DetectedProtocol::MemcachedText | DetectedProtocol::MemcachedBinary => {
            reject_protocol_tls_if_needed(
                &client,
                &state,
                &entry.domain,
                fake_addr,
                client_addr.clone(),
                client_process.clone(),
                "memcached",
            )
            .await?;
            let wire_protocol = if protocol == Some(DetectedProtocol::MemcachedBinary) {
                MemcachedWireProtocol::Binary
            } else {
                MemcachedWireProtocol::Text
            };
            handle_connected_memcached(
                client,
                upstream,
                state,
                memcached_context(
                    &entry,
                    fake_addr,
                    upstream_addr,
                    client_addr,
                    client_process,
                ),
                wire_protocol,
            )
            .await
        }
        DetectedProtocol::Kafka => {
            handle_connected_kafka(
                client,
                upstream,
                state,
                KafkaConnectionContext {
                    client_addr,
                    client_process,
                    target_host: entry.domain.clone(),
                    target_port: fake_addr.port(),
                    target_addr: format!("{}:{}", entry.domain, fake_addr.port()),
                    upstream_addr: upstream_addr.to_string(),
                },
            )
            .await
        }
        DetectedProtocol::Motan => {
            handle_connected_motan(
                client,
                upstream,
                state,
                MotanConnectionContext {
                    client_addr,
                    client_process,
                    target_host: entry.domain.clone(),
                    target_port: fake_addr.port(),
                    target_addr: format!("{}:{}", entry.domain, fake_addr.port()),
                    advertised_ip: match fake_addr {
                        SocketAddr::V4(address) => *address.ip(),
                        SocketAddr::V6(_) => unreachable!("fake-IP gateway only accepts IPv4"),
                    },
                    upstream_addr: upstream_addr.to_string(),
                },
            )
            .await
        }
        DetectedProtocol::Tls => Err(anyhow!(
            "TLS-looking connection was not eligible for HTTPS MITM on port {}",
            fake_addr.port()
        )),
        DetectedProtocol::Http | DetectedProtocol::Raw => {
            let operation_class = OperationClass::Unknown;
            if state.access_decision(operation_class) == AccessDecision::Reject {
                state
                    .record_readonly_rejection(
                        "raw_tcp",
                        operation_class,
                        "raw_stream",
                        client_addr.clone(),
                        client_process.clone(),
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
                        client_process,
                        domain: Some(entry.domain),
                        fake_addr,
                        upstream_addr: Some(upstream_addr),
                        client_to_server_bytes: client_to_server,
                        server_to_client_bytes: server_to_client,
                        duration_ms: started.elapsed().as_millis(),
                        error: None,
                    },
                )
                .await;
            }
            Ok(())
        }
    }
}

fn redis_context(
    entry: &FakeDnsEntry,
    fake_addr: SocketAddr,
    upstream_addr: SocketAddr,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
) -> RedisConnectionContext {
    RedisConnectionContext {
        client_addr,
        client_process,
        target_host: entry.domain.clone(),
        target_port: fake_addr.port(),
        target_addr: format!("{}:{}", entry.domain, fake_addr.port()),
        upstream_addr: upstream_addr.to_string(),
    }
}

fn memcached_context(
    entry: &FakeDnsEntry,
    fake_addr: SocketAddr,
    upstream_addr: SocketAddr,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
) -> MemcachedConnectionContext {
    MemcachedConnectionContext {
        client_addr,
        client_process,
        target_host: entry.domain.clone(),
        target_port: fake_addr.port(),
        target_addr: format!("{}:{}", entry.domain, fake_addr.port()),
        upstream_addr: upstream_addr.to_string(),
    }
}

async fn reject_protocol_tls_if_needed(
    client: &TcpStream,
    state: &AppState,
    domain: &str,
    fake_addr: SocketAddr,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
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
            client_process,
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
    } else if detection.memcached_port_hints.contains(&port) {
        Some(DetectedProtocol::MemcachedText)
    } else if detection.kafka_port_hints.contains(&port) {
        Some(DetectedProtocol::Kafka)
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
    } else if detection.memcached_port_hints.contains(&port) {
        Some("memcached")
    } else {
        None
    }
}

async fn peek_client_protocol(stream: &TcpStream) -> Result<Detection> {
    peek_client_protocol_with_timeout(stream, INITIAL_PEEK_TIMEOUT).await
}

async fn peek_client_protocol_with_timeout(
    stream: &TcpStream,
    wait: Duration,
) -> Result<Detection> {
    let mut buf = vec![0_u8; MAX_SNIFF_BYTES];
    let len = match timeout(wait, stream.peek(&mut buf)).await {
        Ok(result) => result?,
        Err(_) => return Ok(Detection::NeedMore),
    };
    let mut detection = detect_client_protocol(&buf[..len]);
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
            detection = detect_client_protocol(&buf[..len]);
        }
    }
    Ok(detection)
}

async fn upstream_looks_like_mysql(stream: &TcpStream) -> Result<bool> {
    let mut buf = [0_u8; 5];
    let mut len = match timeout(INITIAL_PEEK_TIMEOUT, stream.peek(&mut buf)).await {
        Ok(result) => result?,
        Err(_) => return Ok(false),
    };
    let deadline = tokio::time::Instant::now() + PARTIAL_PEEK_TIMEOUT;
    while detect_mysql_server(&buf[..len]) == Detection::NeedMore
        && len < buf.len()
        && tokio::time::Instant::now() < deadline
    {
        sleep(Duration::from_millis(5)).await;
        len = stream.peek(&mut buf).await?;
    }
    Ok(detect_mysql_server(&buf[..len]) == Detection::Match(DetectedProtocol::Mysql))
}

pub(super) fn upstream_addr(entry: &FakeDnsEntry, port: u16) -> Result<SocketAddr> {
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
mod tests {
    use super::*;
    use crate::config::{TcpApplicationProtocol, TcpProtocolOverrideConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn exact_override_wins_over_port_hints() {
        let mut config = crate::TcpProtocolDetectionConfig::default();
        config.overrides.push(TcpProtocolOverrideConfig {
            host: "cache.internal".to_string(),
            port: 6379,
            protocol: TcpApplicationProtocol::Raw,
        });
        assert_eq!(
            protocol_override(&config, "CACHE.INTERNAL.", 6379),
            Some(DetectedProtocol::Raw)
        );
    }

    #[tokio::test]
    async fn configured_listener_accepts_connections() {
        let listener = bind_listener("127.0.0.1:0".parse().unwrap(), 4096).unwrap();
        let addr = listener.local_addr().unwrap();
        let client_task = tokio::spawn(TcpStream::connect(addr));

        let (_, peer_addr) = listener.accept().await.unwrap();

        assert!(peer_addr.ip().is_loopback());
        client_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn fragmented_sniff_waits_for_a_complete_command_without_consuming_it() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let command = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n".to_vec();
        let writer = command.clone();
        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            for byte in writer {
                client.write_all(&[byte]).await.unwrap();
                sleep(Duration::from_millis(2)).await;
            }
        });
        let (mut server, _) = listener.accept().await.unwrap();

        assert_eq!(
            peek_client_protocol(&server).await.unwrap(),
            Detection::Match(DetectedProtocol::Redis)
        );
        let mut actual = vec![0_u8; command.len()];
        server.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, command);
        client_task.await.unwrap();
    }
}
