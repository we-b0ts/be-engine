use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HOST, HeaderName, HeaderValue};
use hyper::http::uri::{Authority, PathAndQuery, Scheme};
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};

use crate::ProxyClient;
use crate::config::HttpGatewayFixedResponseConfig;
use crate::http::forward::{HostHeaderPolicy, append_end_to_end_headers};

pub(crate) type GatewayBody = BoxBody<Bytes, Infallible>;

pub(crate) async fn send_upstream(
    client: &ProxyClient,
    request: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
    client.request(request).await
}

pub(super) fn upstream_socket_addr(base: &str) -> Option<SocketAddr> {
    let uri = base.parse::<Uri>().ok()?;
    let scheme = uri.scheme_str().unwrap_or("http");
    let authority = uri.authority()?;
    let port = authority.port_u16().or(match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    })?;
    let ip = if authority.host().eq_ignore_ascii_case("localhost") {
        IpAddr::from([127, 0, 0, 1])
    } else {
        authority.host().parse::<IpAddr>().ok()?
    };
    Some(SocketAddr::new(ip, port))
}

pub(crate) fn build_upstream_uri(base: &str, original_uri: &Uri) -> Result<Uri> {
    let base = base
        .parse::<Uri>()
        .with_context(|| format!("invalid gateway upstream URI {base}"))?;
    let scheme = base
        .scheme()
        .cloned()
        .ok_or_else(|| anyhow!("gateway upstream URI missing scheme"))?;
    let authority = base
        .authority()
        .cloned()
        .ok_or_else(|| anyhow!("gateway upstream URI missing authority"))?;
    let path_and_query = original_uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));

    let mut parts = hyper::http::uri::Parts::default();
    parts.scheme = Some(Scheme::try_from(scheme.as_str())?);
    parts.authority = Some(Authority::try_from(authority.as_str())?);
    parts.path_and_query = Some(path_and_query);
    Uri::from_parts(parts).context("failed to construct gateway upstream URI")
}

pub(crate) fn build_upstream_request(
    method: &Method,
    uri: Uri,
    body: Bytes,
    source_headers: &HeaderMap,
    preserve_host: bool,
) -> Result<Request<Full<Bytes>>> {
    let mut builder = Request::builder().method(method).uri(uri.clone());
    let headers = builder.headers_mut().expect("request builder headers");
    let host_policy = if preserve_host {
        HostHeaderPolicy::Preserve
    } else {
        HostHeaderPolicy::Replace
    };
    append_end_to_end_headers(source_headers, headers, host_policy);
    if !preserve_host && let Some(authority) = uri.authority() {
        headers.insert(HOST, authority.as_str().parse()?);
    }
    builder
        .body(Full::new(body))
        .context("failed to build gateway upstream request")
}

pub(crate) fn build_downstream_response(
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

pub(crate) fn simple_response(status: StatusCode, body: &str) -> Response<GatewayBody> {
    Response::builder()
        .status(status)
        .body(boxed_body(Bytes::copy_from_slice(body.as_bytes())))
        .expect("valid static response")
}

pub(super) fn build_fixed_response(
    config: &HttpGatewayFixedResponseConfig,
) -> Response<GatewayBody> {
    let mut builder = Response::builder().status(config.status);
    let headers = builder.headers_mut().expect("fixed response headers");
    if let Some(content_type) = &config.content_type {
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type).expect("validated fixed response content type"),
        );
    }
    for (name, value) in &config.headers {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("validated fixed response header name"),
            HeaderValue::from_str(value).expect("validated fixed response header value"),
        );
    }
    builder
        .body(boxed_body(Bytes::copy_from_slice(config.body.as_bytes())))
        .expect("validated fixed response")
}

fn boxed_body(bytes: Bytes) -> GatewayBody {
    Full::new(bytes).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_target_uri_from_original_path() {
        let uri =
            build_upstream_uri("http://127.0.0.1:9000", &"/hello?a=1".parse().unwrap()).unwrap();
        assert_eq!(uri.to_string(), "http://127.0.0.1:9000/hello?a=1");
    }

    #[test]
    fn builds_configured_fixed_response() {
        let response = build_fixed_response(&HttpGatewayFixedResponseConfig {
            status: 201,
            content_type: Some("application/json".to_string()),
            headers: std::collections::BTreeMap::from([(
                "x-fallback".to_string(),
                "fixed".to_string(),
            )]),
            body: r#"{"code":"created"}"#.to_string(),
        });
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()["x-fallback"], "fixed");
    }
}
