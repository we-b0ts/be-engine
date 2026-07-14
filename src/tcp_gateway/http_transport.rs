use std::convert::Infallible;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::header::HOST;
use hyper::http::uri::{Authority, PathAndQuery, Scheme};
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};

use crate::http::forward::{HostHeaderPolicy, append_end_to_end_headers};

pub(super) type GatewayBody = BoxBody<Bytes, Infallible>;

pub(super) fn build_upstream_uri(upstream_addr: SocketAddr, original_uri: &Uri) -> Result<Uri> {
    let path_and_query = original_uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    let mut parts = hyper::http::uri::Parts::default();
    parts.scheme = Some(Scheme::HTTP);
    parts.authority = Some(Authority::try_from(upstream_addr.to_string())?);
    parts.path_and_query = Some(path_and_query);
    Uri::from_parts(parts).context("failed to construct fake-IP HTTP upstream URI")
}

pub(super) fn build_origin_form_uri(original_uri: &Uri) -> Result<Uri> {
    let path_and_query = original_uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    let mut parts = hyper::http::uri::Parts::default();
    parts.path_and_query = Some(path_and_query);
    Uri::from_parts(parts).context("failed to construct fake-IP HTTPS upstream URI")
}

pub(super) fn build_upstream_request(
    method: &Method,
    uri: Uri,
    body: Bytes,
    source_headers: &HeaderMap,
    domain: &str,
    original_port: u16,
    upstream_authority: Option<&str>,
) -> Result<Request<Full<Bytes>>> {
    let mut builder = Request::builder().method(method).uri(uri);
    let headers = builder.headers_mut().expect("request builder headers");
    let host_policy = if upstream_authority.is_some() {
        HostHeaderPolicy::Replace
    } else {
        HostHeaderPolicy::Preserve
    };
    append_end_to_end_headers(source_headers, headers, host_policy);
    if let Some(upstream_authority) = upstream_authority {
        headers.insert(HOST, upstream_authority.parse()?);
    } else if !headers.contains_key(HOST) {
        let host = if original_port == 80 {
            domain.to_string()
        } else {
            format!("{domain}:{original_port}")
        };
        headers.insert(HOST, host.parse()?);
    }
    builder
        .body(Full::new(body))
        .context("failed to build fake-IP HTTP upstream request")
}

pub(super) fn build_downstream_response(
    status: StatusCode,
    headers: &HeaderMap,
    body: Bytes,
) -> Response<GatewayBody> {
    let mut builder = Response::builder().status(status);
    let out_headers = builder.headers_mut().expect("response builder headers");
    append_end_to_end_headers(headers, out_headers, HostHeaderPolicy::Preserve);
    builder
        .body(boxed_body(body))
        .unwrap_or_else(|_| simple_response(StatusCode::BAD_GATEWAY, "failed to build response"))
}

pub(super) fn simple_response(status: StatusCode, body: &str) -> Response<GatewayBody> {
    Response::builder()
        .status(status)
        .body(boxed_body(Bytes::copy_from_slice(body.as_bytes())))
        .expect("valid static response")
}

fn boxed_body(bytes: Bytes) -> GatewayBody {
    Full::new(bytes).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_http_upstream_uri_with_original_path() {
        let uri = build_upstream_uri(
            "127.0.0.1:8080".parse().unwrap(),
            &"/hello?a=1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(uri.to_string(), "http://127.0.0.1:8080/hello?a=1");
    }

    #[test]
    fn response_alias_replaces_host_for_local_upstream() {
        let mut source_headers = HeaderMap::new();
        source_headers.insert(HOST, "k8s-cluster.pluto-eci.trp.test:8001".parse().unwrap());
        let request = build_upstream_request(
            &Method::GET,
            "/api".parse().unwrap(),
            Bytes::new(),
            &source_headers,
            "k8s-cluster.pluto-eci.trp.test",
            8001,
            Some("127.0.0.1:8001"),
        )
        .unwrap();

        assert_eq!(request.headers()[HOST], "127.0.0.1:8001");
    }
}
