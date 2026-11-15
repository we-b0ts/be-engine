//! Bounded, field-specific input diagnostics without rendering JWTs or key values.
use super::*;

impl ResponseJwtRule {
    /// Format-only discovery and redaction; never proves signature or rule eligibility.
    pub(crate) fn is_candidate(raw: &str) -> bool {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let compact = |raw: &str| {
            if raw.len() > 64 * 1024 {
                return false;
            }
            let parts = raw.split('.').collect::<Vec<_>>();
            if parts.len() != 3 {
                return false;
            }
            let json = |part: &str| {
                URL_SAFE_NO_PAD
                    .decode(part)
                    .ok()
                    .and_then(|bytes| crate::json_value::parse(&bytes))
            };
            json(parts[0]).is_some_and(|v| {
                matches!(
                    v["alg"].as_str(),
                    Some("HS256" | "HS384" | "HS512" | "RS256")
                )
            }) && json(parts[1]).is_some_and(|v| v.is_object())
                && URL_SAFE_NO_PAD.decode(parts[2]).is_ok()
        };
        compact(raw) || crate::request_rules::jwt::url_query::has_candidate_matching(raw, compact)
    }

    pub fn parse_json(raw: &str) -> std::result::Result<Self, String> {
        if raw.len() > 64 * 1024 {
            return Err("response_jwt_input_too_large".into());
        }
        let value = crate::json_value::parse(raw.as_bytes()).ok_or("response_jwt_invalid_json")?;
        if let Some(algorithm) = value.get("algorithm").and_then(serde_json::Value::as_str)
            && !["HS256", "HS384", "HS512", "RS256"].contains(&algorithm)
        {
            return Err("response_jwt_unsupported_algorithm: field=algorithm; supported=HS256,HS384,HS512,RS256".into());
        }
        if let Some(kind) = value
            .pointer("/signing_key_source/kind")
            .and_then(serde_json::Value::as_str)
            && !["target_env", "target_file", "recorded_mysql"].contains(&kind)
        {
            return Err("response_jwt_unsupported_key_source: field=signing_key_source.kind; supported=target_env,target_file,recorded_mysql".into());
        }
        serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(raw)).map_err(
            |error| {
                format!(
                    "response_jwt_invalid_field: field={}; check required fields and value types",
                    error.path()
                )
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn response_jwt_input_reports_capabilities_and_field_paths_without_values() {
        let base = json!({"pointer":"/token","algorithm":"RS256","signing_key_source":{"kind":"target_env","name":"PUBLIC_KEY"},"source_evidence":"issuer signs RSA tokens"});
        assert!(ResponseJwtRule::parse_json(&base.to_string()).is_ok());
        for (field, value, code) in [
            ("algorithm", json!("RS384"), "unsupported_algorithm"),
            ("ttl", json!(12345), "invalid_field"),
        ] {
            let mut value2 = base.clone();
            value2[field] = value;
            let error = ResponseJwtRule::parse_json(&value2.to_string()).unwrap_err();
            assert!(error.contains(code) && error.contains(field), "{error}");
            assert!(!error.contains("12345"));
        }
        let mut value = base;
        value["signing_key_source"]["kind"] = json!("arbitrary_database");
        let error = ResponseJwtRule::parse_json(&value.to_string()).unwrap_err();
        assert!(error.contains("unsupported_key_source") && error.contains("recorded_mysql"));
        assert!(
            ResponseJwtRule::parse_json(r#"{"algorithm":"RS256","algorithm":"HS256"}"#)
                .unwrap_err()
                .contains("invalid_json")
        );
        assert!(serde_json::from_str::<crate::request_rules::JwtAlgorithm>(r#""RS256""#).is_err());
    }
}
