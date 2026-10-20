use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::ProxyClient;

mod observation;
pub(crate) use observation::{
    ObservedConnector, UpstreamTermination, send_https_observed, send_observed,
};

pub(crate) fn new_proxy_client() -> ProxyClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new()).build(ObservedConnector::new(https))
}
