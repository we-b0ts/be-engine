//! HTTP boundary framing and private Recorder control headers.

use super::*;

pub(super) const FINITE_RESPONSE: &str = "x-traffic-e2e-finite-response";

pub(super) const CASE_ID: &str = "x-traffic-e2e-case-id";
pub(super) const SESSION_ID: &str = "x-traffic-e2e-session-id";

pub(super) fn full(bytes: Bytes) -> RelayBody {
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

pub(super) fn response(status: StatusCode, message: &'static str) -> Response<RelayBody> {
    Response::builder()
        .status(status)
        .body(full(Bytes::from_static(message.as_bytes())))
        .unwrap()
}

pub(super) fn strip_private(headers: &mut hyper::HeaderMap) {
    headers.remove(FINITE_RESPONSE);
    headers.remove(CASE_ID);
    headers.remove(SESSION_ID);
}

pub(super) fn socket_sid(request: &Request<Incoming>) -> Option<String> {
    if crate::gateway::http::interaction::request_protocol(request)
        != Some(crate::interaction::model::Protocol::SocketIo)
    {
        return None;
    }
    url::form_urlencoded::parse(request.uri().query()?.as_bytes())
        .find(|(key, _)| key == "sid")
        .map(|(_, value)| value.into_owned())
}

pub(super) fn websocket(request: &Request<Incoming>) -> bool {
    request
        .headers()
        .get("upgrade")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
}

pub(super) fn is_interaction(request: &Request<Incoming>) -> bool {
    crate::gateway::http::interaction::request_protocol(request).is_some()
}

pub(super) fn remove_hop_headers(headers: &mut hyper::HeaderMap) {
    remove_hop_headers_with_upgrade(headers, false);
}

pub(super) fn remove_response_hop_headers(headers: &mut hyper::HeaderMap) {
    let trailers = headers
        .get_all(hyper::header::TRAILER)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    remove_hop_headers(headers);
    for trailer in trailers {
        headers.append(hyper::header::TRAILER, trailer);
    }
}

pub(super) fn remove_hop_headers_with_upgrade(headers: &mut hyper::HeaderMap, upgrade: bool) {
    let named: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(str::trim))
        .filter_map(|v| v.parse::<hyper::header::HeaderName>().ok())
        .collect();
    for name in named {
        if !upgrade || name != "upgrade" {
            headers.remove(name);
        }
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        if !upgrade || (name != "connection" && name != "upgrade") {
            headers.remove(name);
        }
    }
}
