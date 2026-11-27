//! HTTP wire recognition and native message adaptation.
pub mod body_capture;
pub mod client;
pub mod content_encoding;
pub mod forward;
pub mod headers;
pub mod index;
pub mod interaction;
pub mod message;
pub mod multipart;
pub mod native;
pub mod origin;
pub mod path_pattern;
pub mod query_token;
pub mod request_metadata;
pub mod request_sigv4;
pub mod response_headers;
pub mod sse;
pub mod stream_capture;
pub mod termination;
pub mod wire_events;
use traffic_protocol::{Peer, Probe, Recognition};

pub fn recognize(probe: Probe<'_>) -> Recognition {
    if probe.peer != Peer::Client {
        return Recognition::Reject;
    }
    let bytes = probe.bytes;
    if bytes.is_empty() {
        return Recognition::NeedMore;
    }
    let Some(end) = bytes.windows(2).position(|pair| pair == b"\r\n") else {
        return if bytes.len() < 4096
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_graphic() || *byte == b' ' || *byte == b'\r')
        {
            Recognition::NeedMore
        } else {
            Recognition::Reject
        };
    };
    let Ok(line) = std::str::from_utf8(&bytes[..end]) else {
        return Recognition::Reject;
    };
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if !method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        && !target.is_empty()
        && matches!(version, "HTTP/1.0" | "HTTP/1.1")
        && parts.next().is_none()
    {
        Recognition::Match
    } else {
        Recognition::Reject
    }
}

pub mod stream;

/// HTTP uses Hyper's native framing, streaming and upgrade parser. Caller-owned
/// transports and services retain scheduling, capture, policy and storage.
pub struct HttpProvider;

/// Native HTTP driver configuration. Hyper retains HTTP framing, streaming and
/// upgrade state, and the framework supplies its transport and request service.
pub trait HttpConnectionSession: Send {
    fn configure(
        &mut self,
        builder: &mut hyper::server::conn::http1::Builder,
        preserve_header_case: bool,
    );
}

pub type HttpSession = Box<dyn HttpConnectionSession>;

struct NativeHttpSession;

impl HttpConnectionSession for NativeHttpSession {
    fn configure(
        &mut self,
        builder: &mut hyper::server::conn::http1::Builder,
        preserve_header_case: bool,
    ) {
        builder
            .half_close(true)
            .preserve_header_case(preserve_header_case)
            .title_case_headers(preserve_header_case);
    }
}

impl traffic_protocol::DependencyProvider for HttpProvider {
    fn name(&self) -> &'static str {
        "http"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["https"]
    }
    fn native_protocol(
        &self,
    ) -> Option<std::sync::Arc<dyn traffic_protocol::connection::NativeProtocol>> {
        Some(std::sync::Arc::new(native::Native))
    }

    fn report_codec(&self) -> Option<std::sync::Arc<dyn traffic_protocol::report::ReportCodec>> {
        Some(std::sync::Arc::new(report::EvidenceCodec))
    }

    fn evidence(&self) -> Option<std::sync::Arc<dyn traffic_protocol::evidence::EvidenceAdapter>> {
        Some(std::sync::Arc::new(evidence::NativeEvidence))
    }

    fn recognize(&self, probe: traffic_protocol::Probe<'_>) -> traffic_protocol::Recognition {
        recognize(probe)
    }

    fn create_session(&self) -> anyhow::Result<traffic_protocol::Session> {
        Ok(traffic_protocol::Session::new::<HttpSession>(Box::new(
            NativeHttpSession,
        )))
    }
}

impl HttpProvider {
    pub fn connection<I, S, B>(
        io: I,
        service: S,
        preserve_header_case: bool,
    ) -> hyper::server::conn::http1::Connection<hyper_util::rt::TokioIo<I>, S>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        S: hyper::service::Service<
                hyper::Request<hyper::body::Incoming>,
                Response = hyper::Response<B>,
            >,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        B: http_body::Body + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        (&mut NativeHttpSession as &mut dyn HttpConnectionSession).connection(
            io,
            service,
            preserve_header_case,
        )
    }
}

impl dyn HttpConnectionSession + '_ {
    pub fn connection<I, S, B>(
        &mut self,
        io: I,
        service: S,
        preserve_header_case: bool,
    ) -> hyper::server::conn::http1::Connection<hyper_util::rt::TokioIo<I>, S>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        S: hyper::service::Service<
                hyper::Request<hyper::body::Incoming>,
                Response = hyper::Response<B>,
            >,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        B: http_body::Body + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut builder = hyper::server::conn::http1::Builder::new();
        self.configure(&mut builder, preserve_header_case);
        builder.serve_connection(hyper_util::rt::TokioIo::new(io), service)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line_supports_fragmentation_and_native_http_methods() {
        let line = b"PROPFIND /items HTTP/1.1\r\n";
        for length in 0..line.len() {
            assert_eq!(
                recognize(Probe {
                    peer: Peer::Client,
                    bytes: &line[..length]
                }),
                Recognition::NeedMore
            );
        }
        assert_eq!(
            recognize(Probe {
                peer: Peer::Client,
                bytes: line
            }),
            Recognition::Match
        );
        assert_eq!(
            recognize(Probe {
                peer: Peer::Client,
                bytes: b"get key\r\n"
            }),
            Recognition::Reject
        );
    }
}

pub mod events;

pub mod evidence;

pub mod capture;

pub mod recorded;
pub mod response;
pub mod uri;

pub mod candidate;

mod recording_summary;

pub mod limits;
pub mod witness;

pub mod data_stream;

pub mod header_values;

pub mod request_contract;

pub mod report;
