use crate::policy::{compile_policy, parse_policy, render_policy};

const POLICY: &str = r#"format: traffic-policy/v2
json:
  fields:
    /url:
      kind: template
      formats:
        - template: 'wss://vnc.example/sessions/{session_id}?ticket={ticket}'
          fields:
            session_id: {prefix: vnc-, base64url: 24}
            ticket: {base64url: 43}
"#;

#[test]
fn global_template_roundtrip_keeps_one_carrier_independent_format_and_runtime_fingerprint() {
    let policy = parse_policy(POLICY).unwrap();
    let compiled = compile_policy(&policy).unwrap();
    assert!(compiled.native.is_empty());
    assert!(compiled.rules.is_empty());
    let rendered = render_policy(&policy).unwrap();
    assert!(rendered.contains("kind: template"));
    assert!(!rendered.contains("binding:"));
    assert_eq!(
        compile_policy(&parse_policy(&rendered).unwrap()).unwrap(),
        compiled
    );
    let changed =
        compile_policy(&parse_policy(&POLICY.replace("vnc.example", "other.example")).unwrap())
            .unwrap();
    assert_ne!(compiled.fingerprints.runtime, changed.fingerprints.runtime);
    assert_eq!(compiled.fingerprints.capture, changed.fingerprints.capture);
}

#[test]
fn global_template_schema_rejects_missing_extra_duplicate_or_hidden_format_fields() {
    for invalid in [
        POLICY.replace("            ticket: {base64url: 43}\n", ""),
        POLICY.replace(
            "            ticket: {base64url: 43}",
            "            ticket: {base64url: 43}\n            other: decimal",
        ),
        POLICY.replace(
            "            ticket: {base64url: 43}",
            "            ticket: {base64url: 43}\n            ticket: {base64url: 42}",
        ),
        POLICY.replace("{session_id}?ticket={ticket}", "{session_id}{ticket}"),
        POLICY.replace("{base64url: 43}", "{base64url: 0}"),
        POLICY.replace("{base64url: 43}", "{base64url: 43, binding: ticket}"),
        POLICY.replace("kind: template", "kind: template\n      binding: url"),
    ] {
        assert!(
            crate::policy::parse_and_compile_policy(&invalid).is_err(),
            "accepted {invalid}"
        );
    }
}
