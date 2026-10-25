use super::*;

#[test]
fn all_selected_key_shapes_lower_and_reverse_without_a_binding_declaration() {
    for (pattern, yaml, expected) in [
        (
            "vnc_session:*",
            "{kind: identity, formats: [{prefix: vnc-, base64url: 24}]}",
            NativeKeyContract::Capture {
                template: "vnc_session:vnc-{value}".into(),
                format: KeyIdentityFormat::Base64url { bytes: 18 },
            },
        ),
        (
            "vnc_connect_ticket:*",
            "{kind: identity, formats: [{hex: 64}]}",
            NativeKeyContract::Capture {
                template: "vnc_connect_ticket:{value}".into(),
                format: KeyIdentityFormat::Hex { bytes: 32 },
            },
        ),
        (
            "wework_auth_session:*",
            "{kind: identity, formats: [uuid_v4]}",
            NativeKeyContract::Capture {
                template: "wework_auth_session:{value}".into(),
                format: KeyIdentityFormat::UuidV4,
            },
        ),
        (
            "celery-task-meta-*",
            "{kind: identity, formats: [uuid_v4]}",
            NativeKeyContract::Capture {
                template: "celery-task-meta-{value}".into(),
                format: KeyIdentityFormat::UuidV4,
            },
        ),
        (
            "external_kb_mcp:rate:download:*",
            "{kind: time_window, seconds: 60}",
            NativeKeyContract::TimeWindow {
                window_seconds: 60,
                separator: ':',
                segment_index: None,
            },
        ),
    ] {
        let parsed: KeyFormat = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(parsed.lower(pattern).unwrap(), expected);
        let compact = reverse(pattern, &expected).unwrap().unwrap();
        assert_eq!(compact.lower(pattern).unwrap(), expected);
        let rendered = serde_yaml::to_string(&compact).unwrap();
        assert!(!rendered.contains("{value}") && !rendered.contains("binding"));
        assert_eq!(
            serde_yaml::from_str::<KeyFormat>(&rendered).unwrap(),
            parsed
        );
    }
}

#[test]
fn malformed_lengths_unbounded_selectors_and_unsupported_formats_fail_closed() {
    for yaml in [
        "{kind: identity, formats: []}",
        "{kind: identity, formats: [uuid_v4, uuid_v4]}",
        "{kind: identity, formats: [{hex: 3}]}",
        "{kind: identity, formats: [{hex: 514}]}",
        "{kind: identity, formats: [{base64url: 5}]}",
        "{kind: identity, formats: [{base64url: 343}]}",
        "{kind: identity, formats: [{prefix: '{value}', hex: 32}]}",
        "{kind: identity, formats: [uuid]}",
        "{kind: identity, formats: [{hex: 32, unknown: true}]}",
        "{kind: time_window, seconds: 0}",
        "{kind: time_window, seconds: 31536001}",
        "{kind: time_window, seconds: 60, separator: a}",
        "{kind: time_window, seconds: 60, segment: 64}",
        "{kind: time_window, seconds: 60, relation: exact}",
    ] {
        assert!(
            serde_yaml::from_str::<KeyFormat>(yaml)
                .map_or(true, |format| format.lower("key:*").is_err()),
            "accepted {yaml}"
        );
    }
    let valid: KeyFormat = serde_yaml::from_str("{kind: identity, formats: [uuid_v4]}").unwrap();
    for pattern in ["*", "key", "key:*:*", "{value}:*"] {
        assert!(valid.lower(pattern).is_err(), "accepted {pattern}");
    }
}

#[test]
fn byte_count_conversion_keeps_every_supported_unpadded_base64_size() {
    for bytes in 1..=256 {
        let expected = NativeKeyContract::Capture {
            template: "key:{value}:suffix".into(),
            format: KeyIdentityFormat::Base64url { bytes },
        };
        let authored = reverse("key:*:suffix", &expected).unwrap().unwrap();
        assert_eq!(authored.lower("key:*:suffix").unwrap(), expected);
    }
    let different_suffix = NativeKeyContract::Capture {
        template: "key:{value}:other".into(),
        format: KeyIdentityFormat::UuidV4,
    };
    assert!(
        reverse("key:*:suffix", &different_suffix)
            .unwrap()
            .is_none()
    );
}
