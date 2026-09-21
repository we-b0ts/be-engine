use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hyper::HeaderMap;

pub(crate) const STANDARD_RESPONSE_HEADERS: [&str; 13] = [
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "access-control-expose-headers",
    "access-control-max-age",
    "allow",
    "cache-control",
    "content-disposition",
    "content-type",
    "location",
    "vary",
    "www-authenticate",
];

pub(crate) fn snapshot_standard(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
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

#[cfg(test)]
mod tests {
    use hyper::header::{HeaderValue, VARY};

    use super::*;

    #[test]
    fn snapshot_keeps_only_standard_headers_and_repeated_values() {
        let mut headers = HeaderMap::new();
        headers.append(VARY, HeaderValue::from_static("Origin"));
        headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
        headers.insert("set-cookie", HeaderValue::from_static("secret=value"));

        let snapshot = snapshot_standard(&headers);

        assert_eq!(snapshot["vary"], ["Origin", "Accept-Encoding"]);
        assert!(!snapshot.contains_key("set-cookie"));
    }
}
