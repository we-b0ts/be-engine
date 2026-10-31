use super::*;
use crate::policy::{compile_policy, parse_policy, render_policy};

const POLICY: &str = "format: traffic-policy/v3\njson:\n  fields:\n    /created_at: {kind: time, formats: [unix_seconds]}\n    /item_id: {kind: identity, formats: [uuid, {prefix: msg_, hex: 12}]}\n    /array: {kind: unordered}\n";

#[test]
fn global_formats_roundtrip_without_location_declarations_or_expanded_rules() {
    let document = parse_policy(POLICY).unwrap();
    let compiled = compile_policy(&document).unwrap();
    assert!(compiled.rules.is_empty());
    assert_eq!(compiled.global_json.as_ref().unwrap().fields.len(), 3);
    let rendered = render_policy(&document).unwrap();
    assert!(
        rendered.contains("/created_at: {kind: time, formats: [unix_seconds]}"),
        "{rendered}"
    );
    assert!(!rendered.contains("binding"));
    assert!(!rendered.contains("relation"));
    assert_eq!(
        compile_policy(&parse_policy(&rendered).unwrap()).unwrap(),
        compiled
    );
}

#[test]
fn global_format_changes_affect_full_and_runtime_but_not_capture() {
    let first = compile_policy(&parse_policy(POLICY).unwrap()).unwrap();
    let second = compile_policy(
        &parse_policy(&POLICY.replace("unix_seconds", "unix_milliseconds")).unwrap(),
    )
    .unwrap();
    assert_ne!(first.fingerprints.full, second.fingerprints.full);
    assert_ne!(first.fingerprints.runtime, second.fingerprints.runtime);
    assert_eq!(first.fingerprints.capture, second.fingerprints.capture);
    assert_eq!(
        first.fingerprints.classification,
        second.fingerprints.classification
    );
}

#[test]
fn empty_global_map_preserves_exact_json_and_can_clear_formats() {
    let document = parse_policy("format: traffic-policy/v3\njson: {fields: {}}\n").unwrap();
    let compiled = compile_policy(&document).unwrap();
    assert!(compiled.global_json.unwrap().fields.is_empty());
    assert!(render_policy(&document).unwrap().contains("fields: {}"));
}

#[test]
fn null_is_implicit_and_not_an_authored_format() {
    let document = parse_policy("format: traffic-policy/v3\njson:\n  fields:\n    /time: {kind: time, formats: [unix_seconds]}\n    /id: {kind: identity, formats: [uuid]}\n").unwrap();
    let rendered = render_policy(&document).unwrap();
    assert!(!rendered.contains("null"));
    let plan = compile_policy(&document).unwrap().global_json.unwrap();
    assert!(
        plan.identity_fields(&serde_json::json!({"id":null}))
            .unwrap()
            .is_empty()
    );
    for kind in ["time", "identity"] {
        assert!(parse_policy(&format!("format: traffic-policy/v3\njson:\n  fields:\n    /field: {{kind: {kind}, formats: [null]}}\n")).is_err());
    }
}

#[test]
fn redundant_exact_literal_and_null_format_syntax_is_rejected() {
    for field in [
        "{kind: identity, formats: [uuid, exact]}",
        "{kind: time, formats: [{literal: '1970-01-01 00:00:00'}, sql_datetime]}",
    ] {
        assert!(
            parse_policy(&format!(
                "format: traffic-policy/v3\njson:\n  fields:\n    /field: {field}\n"
            ))
            .is_err()
        );
    }
}

#[test]
fn global_document_rejects_bindings_duplicate_paths_and_ambiguous_selectors() {
    for yaml in [
        POLICY.replace("formats: [uuid, {prefix: msg_, hex: 12}]", "formats: [uuid], binding: item"),
        POLICY.replace("/array: {kind: unordered}", "/created_at: {kind: unordered}"),
        POLICY.replace("/array: {kind: unordered}", "/rows/*/id: {kind: identity, formats: [uuid]}\n    /rows/0/id: {kind: identity, formats: [uuid]}"),
        POLICY.replace("formats: [unix_seconds]", "formats: []"),
        POLICY.replace("formats: [unix_seconds]", "formats: [calendar_date]"),
    ] {
        assert!(parse_policy(&yaml).is_err(), "accepted {yaml}");
    }
}

#[test]
fn wildcard_optional_selection_is_source_driven_and_format_choice_is_ordered() {
    let policy: JsonPolicy = serde_yaml::from_str(
        "fields:\n  /rows/*/id: {kind: identity, formats: [uuid, {prefix: msg_, hex: 12}]}\n",
    )
    .unwrap();
    let compiled = policy.compile().unwrap();
    assert!(
        compiled
            .fields(&serde_json::json!({"rows":[{}]}))
            .unwrap()
            .is_empty()
    );
    let selected = compiled
        .fields(&serde_json::json!({"rows":[{}, {"id":"msg_abcdef123456"}]}))
        .unwrap();
    assert_eq!(selected[0].0, "/rows/1/id");
    assert!(
        matches!(&selected[0].1, FieldContract::Identity {prefix, format:IdentityFormat::Hex(12)} if prefix == "msg_")
    );
    let null = compiled
        .fields(&serde_json::json!({"rows":[{"id":null}]}))
        .unwrap();
    assert_eq!(null.len(), 1);
    assert!(null[0].1.time().is_none());
    assert!(
        compiled
            .identity_fields(&serde_json::json!({"rows":[{"id":null}]}))
            .unwrap()
            .is_empty()
    );
    let fixed = compiled
        .identity_fields(&serde_json::json!({"rows":[{"id":"unrecognized"}]}))
        .unwrap();
    assert!(matches!(fixed[0].1, FieldContract::IdentityAnchor));
}

#[test]
fn redis_scalar_formats_roundtrip_and_change_only_comparison_identities() {
    let raw = "format: traffic-policy/v3\nredis:\n  keys:\n    'task-run-monitor:v2:as-of': {kind: time, formats: [unix_seconds]}\n    'session:*': {kind: identity, formats: [uuid]}\n";
    let policy = parse_policy(raw).unwrap();
    let compiled = compile_policy(&policy).unwrap();
    let rendered = render_policy(&policy).unwrap();
    assert_eq!(parse_policy(&rendered).unwrap(), policy);
    assert!(rendered.contains("{kind: time, formats: [unix_seconds]}"));
    let changed =
        compile_policy(&parse_policy(&raw.replace("unix_seconds", "unix_milliseconds")).unwrap())
            .unwrap();
    assert_ne!(compiled.fingerprints.full, changed.fingerprints.full);
    assert_ne!(compiled.fingerprints.runtime, changed.fingerprints.runtime);
    assert_eq!(compiled.fingerprints.capture, changed.fingerprints.capture);
    assert_eq!(
        compiled.fingerprints.classification,
        changed.fingerprints.classification
    );
}

#[test]
fn global_mysql_and_redis_formats_reject_retired_database_selectors() {
    for body in [
        "mysql: {database: app, tables: {}}",
        "redis: {database: 0, keys: {}}",
    ] {
        assert!(parse_policy(&format!("format: traffic-policy/v3\n{body}\n")).is_err());
    }
    let policy = parse_policy("format: traffic-policy/v3\nmysql: {}\nredis: {}\n").unwrap();
    let rendered = render_policy(&policy).unwrap();
    assert!(!rendered.contains("database:"));
    assert_eq!(parse_policy(&rendered).unwrap(), policy);
}

#[test]
fn duration_has_one_unit_and_no_business_condition_syntax() {
    let raw = "format: traffic-policy/v3\njson:\n  fields:\n    /elapsed: {kind: duration, formats: [seconds]}\n";
    let policy = parse_policy(raw).unwrap();
    assert!(
        render_policy(&policy)
            .unwrap()
            .contains("/elapsed: {kind: duration, formats: [seconds]}")
    );
    for invalid in [
        raw.replace("[seconds]", "[seconds, milliseconds]"),
        raw.replace(
            "formats: [seconds]",
            "formats: [seconds], when: {relative_pointer: ../status, equals: running}",
        ),
    ] {
        assert!(parse_policy(&invalid).is_err());
    }
}

#[test]
fn bounded_string_identity_format_roundtrips_with_optional_literal_prefix() {
    let raw = "format: traffic-policy/v3\njson:\n  fields:\n    /_content_key: {kind: identity, formats: [{prefix: 'chat:streaming:block_content:', format: string}]}\n    /access_token: {kind: identity, formats: [string]}\n";
    let policy = parse_policy(raw).unwrap();
    assert_eq!(
        parse_policy(&render_policy(&policy).unwrap()).unwrap(),
        policy
    );
    assert!(matches!(
        policy.json.unwrap().fields["/access_token"],
        GlobalField::Identity { .. }
    ));
}

#[test]
fn url_and_authenticated_jwt_formats_roundtrip_without_carrier_ownership() {
    let raw = "format: traffic-policy/v3\nsignatures:\n  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: SECRET_KEY}}\njson:\n  fields:\n    /download_path: {kind: url, formats: [aws_sigv4]}\n    /headers/origin: {kind: identity, formats: [{string: 255}]}\n    /access_token: {kind: jwt}\n";
    let policy = parse_policy(raw).unwrap();
    let compiled = compile_policy(&policy).unwrap();
    let rendered = render_policy(&policy).unwrap();
    assert_eq!(parse_policy(&rendered).unwrap(), policy);
    assert!(compiled.native.is_empty());
    assert!(rendered.contains("/access_token: {kind: jwt}"));
    assert!(rendered.contains("signatures:"));
    assert!(!rendered.contains("signing_key"));
    assert!(!rendered.contains("claims"));
}

#[test]
fn protocol_declarations_reject_unsupported_branches_scopes_and_scalar_carriers() {
    let prefix = "format: traffic-policy/v3\njson:\n  fields:\n";
    for field in [
        "    /url: {kind: url, formats: []}\n",
        "    /url: {kind: url, formats: [aws_sigv4, aws_sigv4]}\n",
        "    /id: {kind: identity, formats: [jwt_token]}\n",
        "    /id: {kind: identity, formats: [{string: 0}]}\n",
        "    /id: {kind: identity, formats: [{string: 1025}]}\n",
        "    /token: {kind: jwt, formats: [{algorithm: none, signing_key: {kind: startup, source: {kind: target_env, name: SECRET}}}]}\n",
        "    /token: {kind: jwt, formats: [{algorithm: HS256, signing_key: {kind: startup, source: {kind: target_env, name: SECRET}}}, {algorithm: HS256, signing_key: {kind: startup, source: {kind: target_env, name: OTHER}}}]}\n",
        "    /rows/*/token: {kind: jwt, formats: [{algorithm: HS256, signing_key: {kind: startup, source: {kind: target_env, name: SECRET}}, expires_at: /other/*/expires}]}\n",
    ] {
        assert!(
            parse_policy(&format!("{prefix}{field}")).is_err(),
            "accepted {field}"
        );
    }
    for format in [
        "{kind: url, formats: [aws_sigv4]}",
        "{kind: jwt, formats: [{algorithm: HS256, signing_key: {kind: startup, source: {kind: target_env, name: SECRET}}}]}",
    ] {
        for carrier in [
            format!("redis: {{keys: {{token: {format}}}}}"),
            format!("mysql: {{tables: {{t: {{pattern: t, fields: {{token: {format}}}}}}}}}"),
        ] {
            assert!(
                parse_policy(&format!("format: traffic-policy/v3\n{carrier}\n")).is_err(),
                "accepted {carrier}"
            );
        }
    }
}

#[test]
fn bounded_random_string_formats_cover_all_existing_native_lengths() {
    for field in [
        "{kind: identity, formats: [{prefix: id_, hex: 1024}]}",
        "{kind: identity, formats: [{base64url: 1024}]}",
    ] {
        let raw = format!("format: traffic-policy/v3\njson:\n  fields:\n    /id: {field}\n");
        assert!(parse_policy(&raw).is_ok());
        assert!(parse_policy(&raw.replace("1024", "1025")).is_err());
    }
}

#[test]
fn authored_opaque_jwt_identity_formats_are_retired_in_every_scalar_carrier() {
    for formats in ["[jwt]", "[{prefix: 'Bearer ', format: jwt}]", "[uuid, jwt]"] {
        for declaration in [
            format!("json: {{fields: {{'/token': {{kind: identity, formats: {formats}}}}}}}"),
            format!("redis: {{keys: {{token: {{kind: identity, formats: {formats}}}}}}}"),
            format!(
                "mysql: {{tables: {{tokens: {{pattern: tokens, fields: {{token: {{kind: identity, formats: {formats}}}}}}}}}}}"
            ),
            format!("http: {{headers: {{authorization: {{kind: identity, formats: {formats}}}}}}}"),
        ] {
            let error = parse_policy(&format!("format: traffic-policy/v3\n{declaration}\n"))
                .err()
                .unwrap();
            assert!(format!("{error:#}").contains("kind: jwt"), "{error:#}");
        }
    }
}
