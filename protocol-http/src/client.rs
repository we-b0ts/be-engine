use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

pub type ProxyClient =
    hyper_util::client::legacy::Client<ObservedConnector, http_body_util::Full<bytes::Bytes>>;

mod observation;
pub use observation::{
    ObservedConnector, ObservedUpstream, UpstreamTermination, send_https_observed, send_observed,
};

pub fn upstream_addr<B>(response: &hyper::Response<B>) -> Option<std::net::SocketAddr> {
    response
        .extensions()
        .get::<hyper_util::client::legacy::connect::HttpInfo>()
        .map(hyper_util::client::legacy::connect::HttpInfo::remote_addr)
}

pub fn new_proxy_client() -> ProxyClient {
    build_proxy_client(true)
}

pub fn new_unpooled_proxy_client() -> ProxyClient {
    build_proxy_client(false)
}

fn build_proxy_client(reuse_idle_connections: bool) -> ProxyClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    let mut builder = Client::builder(TokioExecutor::new());
    if !reuse_idle_connections {
        // Port-forward can delay a peer's EOF until after its socket has closed.
        // Keep active responses intact, but never reuse that idle connection.
        builder.pool_max_idle_per_host(0);
    }
    builder.build(ObservedConnector::new(https))
}
