//! Network facts come from the actual outbound request, independently of responses.
use anyhow::{Context, Result, ensure};
use hyper::Uri;

pub(super) async fn observe_request_attempt(state: &crate::AppState, uri: &Uri) -> Result<()> {
    let endpoint = request_endpoint(uri)?;
    state
        .recorder()
        .observe_accessed_endpoint(&endpoint.host, endpoint.port)
        .await
}

fn request_endpoint(uri: &Uri) -> Result<crate::recording_network::RecordedEndpoint> {
    let host = uri
        .host()
        .context("HTTP proxy outbound request has no host")?;
    let scheme = uri
        .scheme_str()
        .context("HTTP proxy outbound request has no scheme")?;
    ensure!(
        matches!(scheme, "http" | "https"),
        "unsupported HTTP proxy outbound scheme"
    );
    let port = uri
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    crate::recording_network::RecordedEndpoint::new(
        host.trim_start_matches('[').trim_end_matches(']'),
        port,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_request_is_the_only_authority_for_network_identity() {
        for (uri, host, port) in [
            (
                "http://UPSTREAM.test/resource?redirect=https://other.test:9999",
                "upstream.test",
                80,
            ),
            ("https://secure.test/resource", "secure.test", 443),
            ("https://secure.test:8443/resource", "secure.test", 8443),
            ("http://[::1]:8080/resource", "::1", 8080),
        ] {
            let endpoint = request_endpoint(&uri.parse().unwrap()).unwrap();
            assert_eq!(endpoint.host, host);
            assert_eq!(endpoint.port, port);
        }
        assert!(request_endpoint(&"/relative".parse().unwrap()).is_err());
    }
}
