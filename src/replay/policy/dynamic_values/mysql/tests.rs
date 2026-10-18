use super::*;

fn pairs() -> [IdentityPair; 1] {
    [IdentityPair {
        source: "old-name".into(),
        target: "new-name".into(),
    }]
}

fn attachment_sql(bytes: usize, name: &str) -> String {
    let prefix = format!("UPDATE attachments SET metadata='{{\"name\":\"{name}\",\"payload\":\"");
    let suffix = "\"}', status='READY' WHERE id=7";
    format!(
        "{prefix}{}{suffix}",
        "x".repeat(bytes - prefix.len() - suffix.len())
    )
}

#[test]
fn attachment_identity_normalization_accepts_recorded_size_and_exact_8_mib_boundary() {
    for bytes in [1_314_248, 8 * 1024 * 1024] {
        let source = attachment_sql(bytes, "old-name");
        let actual = attachment_sql(bytes, "new-name");
        assert_eq!(source.len(), bytes);
        assert_eq!(actual.len(), bytes);
        let source_normalized = normalize_sql(Some(&source), &pairs(), false).unwrap();
        let actual_normalized = normalize_sql(Some(&actual), &pairs(), true).unwrap();
        assert!(
            source_normalized == actual_normalized,
            "normalization mismatch at {bytes} bytes"
        );
        let changed = actual.replacen("\"payload\":\"x", "\"payload\":\"y", 1);
        assert!(source_normalized != normalize_sql(Some(&changed), &pairs(), true).unwrap());
    }
    let oversized = attachment_sql(8 * 1024 * 1024 + 1, "new-name");
    let error = normalize_sql(Some(&oversized), &pairs(), true).unwrap_err();
    assert!(error.to_string().contains("8 MiB and 32768 tokens"));
}

#[test]
fn dynamic_sql_token_limit_accepts_32768_and_rejects_the_next_token() {
    let source = format!("SELECT {}", vec!["'old-name'"; 16_384].join(","));
    let actual = format!("SELECT {}", vec!["'new-name'"; 16_384].join(","));
    assert_eq!(bounds::statement(&source).unwrap().len(), 32_768);
    assert!(
        normalize_sql(Some(&source), &pairs(), false).unwrap()
            == normalize_sql(Some(&actual), &pairs(), true).unwrap()
    );
    assert!(normalize_sql(Some(&format!("{actual},")), &pairs(), true).is_err());
}

#[test]
fn large_mysql_parameters_normalize_embedded_identities_and_preserve_stable_payloads() {
    let source = serde_json::json!({"name":"old-name","payload":"x".repeat(1_314_248)}).to_string();
    let actual = source.replace("old-name", "new-name");
    let bytes = source.as_bytes();
    assert_eq!(
        capture(&Token::Bytes(bytes.into()), Some("/name")).unwrap(),
        "old-name"
    );
    assert!(strings::contains_identity_with_limit(
        bytes,
        &pairs(),
        bounds::MAX_STATEMENT_BYTES
    ));
    assert!(!strings::contains_identity(bytes, &pairs()));
    let parameter = |text| RecordedMysqlValue {
        kind: "string".into(),
        value: Some(Value::String(text)),
        raw: None,
    };
    let normalized = normalize_params(Some(&[parameter(actual)]), &pairs(), true)
        .unwrap()
        .unwrap();
    assert!(normalized[0].value == Some(Value::String(source)));
}

#[test]
fn large_mysql_json_still_rejects_duplicate_identity_fields() {
    let payload = format!(
        "{{\"name\":\"new-name\",\"name\":\"other-name\",\"payload\":\"{}\"}}",
        "x".repeat(1_314_248)
    );
    assert!(capture(&Token::Bytes(payload.as_bytes().into()), Some("/name")).is_err());
    assert!(
        strings::normalize_with_limit(
            payload.as_bytes(),
            &pairs(),
            true,
            bounds::MAX_STATEMENT_BYTES
        )
        .is_err()
    );
}
