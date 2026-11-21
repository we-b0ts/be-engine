use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hyper::HeaderMap;

pub use crate::headers::{STANDARD_RESPONSE_HEADERS, X_REQUEST_ID};

pub fn snapshot_standard(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut snapshot = BTreeMap::<String, Vec<String>>::new();
    for name in STANDARD_RESPONSE_HEADERS {
        for value in headers.get_all(name) {
            snapshot.entry(name.to_string()).or_default().push(
                value
                    .to_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|_| STANDARD.encode(value.as_bytes())),
            );
        }
    }
    snapshot
}

pub fn snapshot_request_context(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut snapshot = BTreeMap::<String, Vec<String>>::new();
    for value in headers.get_all(X_REQUEST_ID) {
        snapshot.entry(X_REQUEST_ID.to_string()).or_default().push(
            value
                .to_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|_| STANDARD.encode(value.as_bytes())),
        );
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use hyper::header::{HeaderValue, VARY};

    use super::*;

    #[test]
    fn snapshots_only_selected_response_and_request_headers() {
        let mut headers = HeaderMap::new();
        headers.append(VARY, HeaderValue::from_static("Origin"));
        headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
        headers.insert(X_REQUEST_ID, HeaderValue::from_static("request-123"));
        headers.insert("set-cookie", HeaderValue::from_static("secret=value"));

        let snapshot = snapshot_standard(&headers);

        assert_eq!(snapshot["vary"], ["Origin", "Accept-Encoding"]);
        assert_eq!(snapshot[X_REQUEST_ID], ["request-123"]);
        assert!(!snapshot.contains_key("set-cookie"));
        assert_eq!(
            snapshot_request_context(&headers),
            BTreeMap::from([(X_REQUEST_ID.to_string(), vec!["request-123".to_string()])])
        );
    }
}
