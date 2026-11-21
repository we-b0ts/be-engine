use std::io::Write;

use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};

use super::*;

fn config() -> HttpResponseRewriteConfig {
    serde_yaml::from_str(
        r#"
rules:
  - name: sandbox-base-url
    authorities: [sandbox.example.test]
    methods: [GET]
    path_pattern: /executor-manager/sandboxes/*
    pointers: [/base_url, /other, /missing, /null]
"#,
    )
    .unwrap()
}

async fn rewrite(
    config: &HttpResponseRewriteConfig,
    registry: &FakeDnsRegistry,
    body: &[u8],
    gzip: bool,
) -> Result<Option<RewrittenResponse>> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json;charset=utf-8".parse()?);
    headers.insert(ETAG, "old".parse()?);
    headers.insert("digest", "stale".parse()?);
    let mut compressed = Vec::new();
    if gzip {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body)?;
        compressed = encoder.finish()?;
        headers.insert(CONTENT_ENCODING, "gzip".parse()?);
    }
    apply(
        &CompiledRewrites::new(config)?,
        registry,
        &KubectlProxyManager::default(),
        "",
        1024 * 1024,
        RewriteInput {
            method: &Method::GET,
            uri: &"/executor-manager/sandboxes/123?ignored=yes".parse()?,
            authority: Some("sandbox.example.test"),
            status: StatusCode::OK,
            headers: &headers,
            body: if gzip { &compressed } else { body },
        },
    )
    .await
}

#[tokio::test]
async fn json_urls_preserve_url_bytes_and_capture_multiple_ports_on_one_ip() {
    let registry = FakeDnsRegistry::new("198.19.0.0/16").unwrap();
    let input = json!({
        "base_url": "http://10.36.14.118:8080/a/../b%2fc?q=A%2fb#frag",
        "other": "https://10.36.14.118:443/x", "null":null, "unselected":"http://10.1.1.1/"
    });
    let output = rewrite(
        &config(),
        &registry,
        &serde_json::to_vec(&input).unwrap(),
        true,
    )
    .await
    .unwrap()
    .unwrap();
    let value: Value = serde_json::from_slice(&output.body).unwrap();
    assert_eq!(
        value["base_url"],
        "http://http-10-36-14-118-8080.trp.test:8080/a/../b%2fc?q=A%2fb#frag"
    );
    assert_eq!(
        value["other"],
        "https://https-10-36-14-118-443.trp.test:443/x"
    );
    assert_eq!(value["unselected"], input["unselected"]);
    assert_eq!(output.discovered_tcp_targets.len(), 2);
    let first = &output.discovered_tcp_targets[0];
    let second = &output.discovered_tcp_targets[1];
    assert_ne!(first.advertised_ip, second.advertised_ip);
    assert_eq!(first.upstream_ip, second.upstream_ip);
    assert!(!output.headers.contains_key(CONTENT_ENCODING));
    assert!(!output.headers.contains_key(ETAG));
    assert!(!output.headers.contains_key("digest"));
    assert_eq!(
        output.headers[CONTENT_LENGTH],
        output.body.len().to_string()
    );
    // Dynamic addresses are learned on every response; a new endpoint gets another route.
    let next = rewrite(
        &config(),
        &registry,
        br#"{"base_url":"http://10.36.14.119:8080"}"#,
        false,
    )
    .await
    .unwrap()
    .unwrap();
    assert_ne!(
        next.discovered_tcp_targets[0].advertised_ip,
        first.advertised_ip
    );
}

#[tokio::test]
async fn generic_rules_skip_missing_null_and_hostname_but_fail_invalid_selected_values() {
    let registry = FakeDnsRegistry::new("198.19.0.0/16").unwrap();
    for body in [
        r#"{}"#,
        r#"{"base_url":null}"#,
        r#"{"base_url":"http://example.test:8080"}"#,
    ] {
        assert!(
            rewrite(&config(), &registry, body.as_bytes(), false)
                .await
                .unwrap()
                .is_none()
        );
    }
    for body in [
        r#"{"base_url":5}"#,
        r#"{"base_url":"invalid"}"#,
        r#"{"base_url":"http://[::1]/"}"#,
        r#"{"base_url":"http://127.1/"}"#,
        r#"{"base_url":"http://10.0.0.1\\evil/path"}"#,
    ] {
        assert!(
            rewrite(&config(), &registry, body.as_bytes(), false)
                .await
                .is_err(),
            "{body}"
        );
    }
    let mut disabled = config();
    disabled.enabled = false;
    assert!(
        rewrite(&disabled, &registry, b"not-json", false)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn patterns_and_default_filters_match_only_supported_responses() {
    let rule = &config().rules[0];
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/problem+json".parse().unwrap());
    for (path, status, expected) in [
        ("/executor-manager/sandboxes/123", StatusCode::OK, true),
        (
            "/executor-manager/sandboxes/123/path",
            StatusCode::OK,
            false,
        ),
        ("/executor-manager/sandboxes/", StatusCode::OK, false),
        (
            "/executor-manager/sandboxes/123",
            StatusCode::NOT_FOUND,
            false,
        ),
    ] {
        assert_eq!(
            matches(
                rule,
                &RewriteInput {
                    method: &Method::GET,
                    uri: &path.parse().unwrap(),
                    authority: Some("sandbox.example.test"),
                    status,
                    headers: &headers,
                    body: b"{}"
                }
            ),
            expected
        );
    }
    let mut deep = rule.clone();
    deep.path_pattern = Some("/executor-manager/sandboxes/**".into());
    assert!(matches(
        &deep,
        &RewriteInput {
            method: &Method::GET,
            uri: &"/executor-manager/sandboxes/123/path".parse().unwrap(),
            authority: Some("sandbox.example.test"),
            status: StatusCode::OK,
            headers: &headers,
            body: b"{}"
        }
    ));
}

#[tokio::test]
async fn matching_generic_rules_combine_pointers() {
    let mut config = config();
    config.rules[0].pointers = vec!["/base_url".into()];
    let mut second = config.rules[0].clone();
    second.name = "another-url".into();
    second.pointers = vec!["/other".into()];
    config.rules.push(second);
    let registry = FakeDnsRegistry::new("198.19.0.0/16").unwrap();
    let result = rewrite(
        &config,
        &registry,
        br#"{"base_url":"http://10.0.0.1:80","other":"http://10.0.0.2:81"}"#,
        false,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.discovered_tcp_targets.len(), 2);
}
