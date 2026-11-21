use hyper::HeaderMap;
use hyper::header::{CONNECTION, HOST};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostHeaderPolicy {
    Preserve,
    Replace,
}

/// Copies HTTP end-to-end headers while excluding transport-specific headers.
pub fn append_end_to_end_headers(
    source: &HeaderMap,
    destination: &mut HeaderMap,
    host_policy: HostHeaderPolicy,
) {
    for (name, value) in source {
        if is_hop_by_hop(name.as_str())
            || (host_policy == HostHeaderPolicy::Replace && name == HOST)
        {
            continue;
        }
        destination.append(name, value.clone());
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || name.eq_ignore_ascii_case(CONNECTION.as_str())
}

#[cfg(test)]
mod tests {
    use hyper::header::{CONNECTION, CONTENT_TYPE, HOST, HeaderValue};

    use super::*;

    #[test]
    fn excludes_hop_by_hop_headers() {
        let mut source = HeaderMap::new();
        source.insert(CONNECTION, HeaderValue::from_static("close"));
        source.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let mut destination = HeaderMap::new();

        append_end_to_end_headers(&source, &mut destination, HostHeaderPolicy::Preserve);

        assert!(!destination.contains_key(CONNECTION));
        assert_eq!(destination[CONTENT_TYPE], "application/json");
    }

    #[test]
    fn optionally_replaces_host_at_the_caller_boundary() {
        let mut source = HeaderMap::new();
        source.insert(HOST, HeaderValue::from_static("client.example"));
        let mut destination = HeaderMap::new();

        append_end_to_end_headers(&source, &mut destination, HostHeaderPolicy::Replace);

        assert!(!destination.contains_key(HOST));
    }
}
