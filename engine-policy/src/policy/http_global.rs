//! HTTP header formats apply to every API and dependency endpoint.
use super::GlobalField;
use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

pub use traffic_protocol_http::header_values::GLOBAL_HTTP_ID;
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpPolicy {
    #[serde(default, deserialize_with = "header_formats")]
    pub headers: BTreeMap<String, GlobalField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_metadata: Vec<traffic_protocol_http::request_metadata::RequestMetadataRule>,
}
fn header_formats<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, GlobalField>, D::Error> {
    let raw = super::strict_map::unique_map(deserializer)?;
    normalize(raw).map_err(serde::de::Error::custom)
}
fn normalize(headers: BTreeMap<String, GlobalField>) -> Result<BTreeMap<String, GlobalField>> {
    Ok(traffic_policy_document::HttpPolicy {
        headers,
        request_metadata: Vec::new(),
    }
    .compile(&super::authoring::context())?
    .headers)
}

impl HttpPolicy {
    pub fn compile(&self) -> Result<Self> {
        traffic_protocol_http::request_metadata::validate_rules(&self.request_metadata)?;
        Ok(Self {
            headers: normalize(self.headers.clone())?,
            request_metadata: self.request_metadata.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn request_metadata_is_exactly_scoped_and_round_trips() {
        let raw = r#"format: traffic-policy/v3
http:
  request_metadata:
    - host: gateway.example
      method: POST
      path: /stream/connect
      json_ipv4: [/localAddress]
"#;
        let policy = crate::policy::parse_policy(raw).unwrap();
        let compiled = crate::policy::compile_policy(&policy).unwrap();
        assert_eq!(compiled.http.as_ref().unwrap().request_metadata.len(), 1);
        let rendered = crate::policy::render_policy(&policy).unwrap();
        assert_eq!(
            crate::policy::parse_and_compile_policy(&rendered).unwrap(),
            compiled
        );
        assert!(crate::policy::parse_policy(&raw.replace("/stream/connect", "/stream/*")).is_err());
        for retired_field in ["traceparent: true", "accept_encoding: gzip"] {
            assert!(
                crate::policy::parse_policy(&format!("{raw}      {retired_field}\n")).is_err(),
                "accepted retired HTTP request metadata field {retired_field}"
            );
        }
    }

    #[test]
    fn header_formats_roundtrip_normalize_names_and_reject_ambiguous_or_non_scalar_declarations() {
        let raw = "format: traffic-policy/v3\nhttp:\n  headers:\n    X-Amz-Date: {kind: time, formats: [amz_date]}\n";
        let policy = crate::policy::parse_policy(raw).unwrap();
        assert!(
            policy
                .http
                .as_ref()
                .unwrap()
                .headers
                .contains_key("x-amz-date")
        );
        let compiled = crate::policy::compile_policy(&policy).unwrap();
        let rendered = crate::policy::render_policy(&policy).unwrap();
        assert!(rendered.contains("x-amz-date: {kind: time, formats: [amz_date]}"));
        assert_eq!(
            crate::policy::parse_and_compile_policy(&rendered).unwrap(),
            compiled
        );
        let changed =
            crate::policy::parse_and_compile_policy(&raw.replace("amz_date", "rfc3339")).unwrap();
        assert_ne!(compiled.fingerprints.runtime, changed.fingerprints.runtime);
        assert_eq!(compiled.fingerprints.capture, changed.fingerprints.capture);
        for invalid in [
            raw.replace("X-Amz-Date:", "bad header:"),
            raw.replace("X-Amz-Date:", "'*':"),
            raw.replace("X-Amz-Date:", "Content-Length:"),
            raw.replace("X-Amz-Date:", "Signature:"),
            raw.replace("{kind: time, formats: [amz_date]}", "{kind: unordered}"),
            format!("{raw}    x-amz-date: {{kind: time, formats: [amz_date]}}\n"),
        ] {
            assert!(
                crate::policy::parse_policy(&invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }
}
