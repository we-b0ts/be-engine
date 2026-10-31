use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use chrono::Utc;
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tracing::{info, warn};
use uuid::Uuid;

use crate::AppState;
use crate::access_policy::{AccessDecision, OperationClass};
use crate::dns_mock::FakeDnsEntry;
use crate::recorder::{BodyCapture, RecorderEvent, UdpDatagramEvent, capture_body};
use crate::recording_control::RecordingListener;

const UDP_RECV_BUFFER_BYTES: usize = 65_535;

pub async fn run(state: AppState) -> Result<()> {
    let config = state.config().udp_gateway.clone();
    let socket = bind_udp_socket(config.listen).with_context(|| {
        format!(
            "failed to bind UDP gateway {}; check `ss -lunp` for UDP port conflicts",
            config.listen
        )
    })?;
    state.mark_recording_listener_ready(RecordingListener::UdpGateway);
    info!(
        listen = %config.listen,
        forward = config.forward,
        "UDP fake-IP gateway listening"
    );
    run_socket(state, socket).await
}

fn bind_udp_socket(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)?;
    enable_original_dst(&socket)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket).context("failed to create Tokio UDP socket")
}

async fn run_socket(state: AppState, socket: UdpSocket) -> Result<()> {
    let listen_addr = socket
        .local_addr()
        .context("failed to read UDP gateway local address")?;
    let mut buf = vec![0_u8; UDP_RECV_BUFFER_BYTES];
    loop {
        let datagram = receive_datagram(&socket, &mut buf)
            .await
            .context("failed to receive UDP gateway datagram")?;
        if let Err(err) = handle_datagram(&state, listen_addr, datagram).await {
            warn!(error = %format!("{err:#}"), "UDP gateway datagram failed");
        }
    }
}

async fn receive_datagram(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<ReceivedDatagram> {
    socket
        .async_io(Interest::READABLE, || {
            recv_udp_datagram(socket.as_raw_fd(), buf)
        })
        .await
}

async fn handle_datagram(
    state: &AppState,
    listen_addr: SocketAddr,
    datagram: ReceivedDatagram,
) -> Result<()> {
    let started = Instant::now();
    let id = Uuid::new_v4();
    let targets =
        state.capture_dependency_start(crate::dependency::observation::ProtocolRef::Observation {
            event_id: id,
            kind: "udp_datagram".into(),
        });
    let fake_addr = datagram.original_dst.unwrap_or(listen_addr);
    let client_addr = Some(datagram.peer.to_string());
    let target = target_from_fake_addr(state, fake_addr).await;
    if let Some(target) = &target {
        state
            .recorder()
            .observe_accessed_endpoint(&target.entry.domain, fake_addr.port())
            .await?;
    }
    let payload = &datagram.payload;
    let kubernetes_route = target
        .as_ref()
        .is_some_and(|target| state.has_recording_upstream(&target.entry.domain));
    let upstream_addr = target
        .as_ref()
        .filter(|_| !kubernetes_route)
        .and_then(|target| upstream_addr(&target.entry, fake_addr.port()).ok());

    let mut error = None;
    let mut forwarded = false;
    let operation_class = OperationClass::Unknown;
    let policy_rejected = state.access_decision(operation_class) == AccessDecision::Reject;
    if policy_rejected {
        state
            .record_readonly_rejection(
                "udp",
                operation_class,
                "datagram",
                client_addr.clone(),
                Some(match &target {
                    Some(target) => format!("{}:{}", target.entry.domain, fake_addr.port()),
                    None => fake_addr.to_string(),
                }),
                "UDP traffic is not allowed by the recording access policy",
            )
            .await;
        error = Some("request blocked by recording access policy".to_string());
    } else if kubernetes_route {
        error = Some(
            "Kubernetes port-forward routes support TCP only; UDP cannot be forwarded".to_string(),
        );
    } else if state.config().udp_gateway.forward {
        match upstream_addr {
            Some(upstream) => {
                if let Err(err) = forward_udp(payload, upstream).await {
                    error = Some(format!("{err:#}"));
                } else {
                    forwarded = true;
                }
            }
            None => {
                error = Some("UDP forwarding requested but upstream target is unknown".to_string());
            }
        }
    }

    let body = capture_body(payload, state.config().recording.max_body_bytes);
    let event = RecorderEvent::UdpDatagram(UdpDatagramEvent {
        id,
        timestamp: Utc::now(),
        listen_addr: listen_addr.to_string(),
        client_addr,
        target_host: target.as_ref().map(|target| target.entry.domain.clone()),
        target_port: Some(fake_addr.port()),
        target_addr: Some(match &target {
            Some(target) => format!("{}:{}", target.entry.domain, fake_addr.port()),
            None => fake_addr.to_string(),
        }),
        fake_addr: datagram.original_dst.map(|addr| addr.to_string()),
        upstream_addr: upstream_addr.map(|addr| addr.to_string()),
        protocol: "udp".to_string(),
        forwarded,
        payload_text: payload_text(&body),
        payload: body,
        duration_ms: started.elapsed().as_millis(),
        error,
    });
    state.record_event_for_targets(event, targets);
    Ok(())
}

struct Target {
    entry: FakeDnsEntry,
}

async fn target_from_fake_addr(state: &AppState, fake_addr: SocketAddr) -> Option<Target> {
    let IpAddr::V4(fake_ip) = fake_addr.ip() else {
        return None;
    };
    state
        .dns_registry()
        .get_by_fake_ip(fake_ip)
        .await
        .map(|entry| Target { entry })
}

async fn forward_udp(payload: &[u8], upstream_addr: SocketAddr) -> Result<()> {
    let bind_addr = match upstream_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind UDP forward socket for {upstream_addr}"))?;
    socket
        .send_to(payload, upstream_addr)
        .await
        .with_context(|| format!("failed to forward UDP datagram to {upstream_addr}"))?;
    Ok(())
}

fn upstream_addr(entry: &FakeDnsEntry, port: u16) -> Result<SocketAddr> {
    let ip = entry
        .real_ips
        .first()
        .copied()
        .ok_or_else(|| anyhow!("DNS mock entry has no real IPs for {}", entry.domain))?;
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

fn payload_text(payload: &BodyCapture) -> Option<String> {
    if payload.truncated {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.data)
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn enable_original_dst(socket: &std::net::UdpSocket) -> Result<()> {
    let enabled: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_RECVORIGDSTADDR,
            &enabled as *const _ as *const libc::c_void,
            mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error()).context("setsockopt IP_RECVORIGDSTADDR failed");
    }
    Ok(())
}

struct ReceivedDatagram {
    peer: SocketAddr,
    original_dst: Option<SocketAddr>,
    payload: Vec<u8>,
}

fn recv_udp_datagram(fd: RawFd, buf: &mut [u8]) -> io::Result<ReceivedDatagram> {
    let mut peer_storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let control_len =
        unsafe { libc::CMSG_SPACE(mem::size_of::<libc::sockaddr_in>() as libc::c_uint) as usize };
    let mut control = vec![0_u8; control_len];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = (&mut peer_storage as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();

    let received = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let peer = sockaddr_storage_to_addr(&peer_storage, msg.msg_namelen)?;
    let original_dst = unsafe { original_dst_from_control(&msg) };
    Ok(ReceivedDatagram {
        peer,
        original_dst,
        payload: buf[..received as usize].to_vec(),
    })
}

unsafe fn original_dst_from_control(msg: &libc::msghdr) -> Option<SocketAddr> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::IPPROTO_IP
            && header.cmsg_type == libc::IP_ORIGDSTADDR
            && header.cmsg_len
                >= (mem::size_of::<libc::cmsghdr>() + mem::size_of::<libc::sockaddr_in>()) as _
        {
            let data = unsafe { libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in };
            let addr = unsafe { std::ptr::read_unaligned(data) };
            return Some(sockaddr_in_to_addr(addr));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    None
}

fn sockaddr_storage_to_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    if len as usize >= mem::size_of::<libc::sockaddr_in>()
        && storage.ss_family as libc::c_int == libc::AF_INET
    {
        let addr =
            unsafe { std::ptr::read_unaligned(storage as *const _ as *const libc::sockaddr_in) };
        return Ok(sockaddr_in_to_addr(addr));
    }
    if len as usize >= mem::size_of::<libc::sockaddr_in6>()
        && storage.ss_family as libc::c_int == libc::AF_INET6
    {
        let addr =
            unsafe { std::ptr::read_unaligned(storage as *const _ as *const libc::sockaddr_in6) };
        return Ok(sockaddr_in6_to_addr(addr));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unsupported UDP sockaddr family",
    ))
}

fn sockaddr_in_to_addr(addr: libc::sockaddr_in) -> SocketAddr {
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    SocketAddr::new(IpAddr::V4(ip), port)
}

fn sockaddr_in6_to_addr(addr: libc::sockaddr_in6) -> SocketAddr {
    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    SocketAddr::new(IpAddr::V6(ip), port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::time::{Duration, timeout};

    #[test]
    fn converts_ipv4_sockaddr() {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: u16::to_be(8125),
            sin_addr: libc::in_addr {
                s_addr: u32::to_be(u32::from(Ipv4Addr::new(127, 0, 0, 1))),
            },
            sin_zero: [0; 8],
        };
        assert_eq!(
            sockaddr_in_to_addr(addr),
            "127.0.0.1:8125".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn waits_for_readiness_again_after_receiving_a_datagram() {
        let socket = bind_udp_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        let listen_addr = socket.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = vec![0_u8; UDP_RECV_BUFFER_BYTES];

        sender.send_to(b"first", listen_addr).await.unwrap();
        let first = timeout(Duration::from_secs(1), receive_datagram(&socket, &mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.payload, b"first");

        let second_receive = receive_datagram(&socket, &mut buf);
        assert!(
            timeout(Duration::from_millis(50), second_receive)
                .await
                .is_err(),
            "empty UDP socket should wait instead of retrying recvmsg"
        );

        sender.send_to(b"second", listen_addr).await.unwrap();
        let second = timeout(Duration::from_secs(1), receive_datagram(&socket, &mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.payload, b"second");
    }

    #[tokio::test]
    async fn records_udp_datagram_as_startup_global_dependency() {
        let temp = tempdir().unwrap();
        let mut config = crate::AppConfig::default();
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let state = crate::AppState::new(config).await.unwrap();
        handle_datagram(
            &state,
            "127.0.0.1:15002".parse().unwrap(),
            ReceivedDatagram {
                peer: "127.0.0.1:42000".parse().unwrap(),
                original_dst: None,
                payload: b"metric.path 1 123\n".to_vec(),
            },
        )
        .await
        .unwrap();
        state
            .recorder()
            .seal_bootstrap_dependencies()
            .await
            .unwrap();

        let dependencies = state.recorder().run_dir.join("global-dependencies.jsonl");
        let raw = crate::recorder::test_io::read_to_string(&dependencies)
            .await
            .unwrap();

        assert!(raw.contains(r#""event_type":"udp_datagram""#), "{raw}");
        assert!(
            raw.contains(r#""payload_text":"metric.path 1 123\n""#),
            "{raw}"
        );
    }
}
