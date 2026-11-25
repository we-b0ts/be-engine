use std::collections::BTreeMap;

use super::*;
mod conditional_identity;
mod http_request;
mod identity_delivery;
use crate::policy::{Endpoint, Resource, compile_native};

fn proven<T>(contract: T) -> Proven<T> {
    Proven {
        contract,
        proof: Some(Proof {
            source: "source.rs:1".into(),
            fact: "one Source constructor supplies this field".into(),
        }),
    }
}

fn path_rule() -> NativeRule {
    let resource = Resource {
        protocol: Protocol::Http,
        endpoint: Endpoint {
            host: "store.example".into(),
            port: 80,
        },
        database: None,
        username: None,
    };
    NativeRule {
        id: "storage-key".into(),
        proof: proven(()).proof,
        when: None,
        selector: NativeMatch {
            api: Some("POST /upload".into()),
            resource: Some(resource.clone()),
            operation: Some("PUT".into()),
            path: Some("/*".into()),
            ..Default::default()
        },
        effect: NativeEffect::Identity(IdentityEffect {
            value_type: IdentityType::String,
            format: None,
            references: vec![proven(IdentityTarget { resource })],
            capture: IdentityCapture::HttpPath {
                segment: PathIdentitySegment {
                    index: 0,
                    template: "{proof}_{fixed}".into(),
                    fields: BTreeMap::from([
                        (
                            "proof".into(),
                            proven(PathIdentityField::Random {
                                format: PathRandomFormat::Hex,
                                length: 12,
                            }),
                        ),
                        ("fixed".into(), proven(PathIdentityField::Exact)),
                    ]),
                },
            },
        }),
    }
}

#[test]
fn response_header_date_defaults_to_utc_without_timezone_configuration() {
    let mut rule = path_rule();
    rule.selector.resource = None;
    rule.selector.operation = None;
    rule.selector.path = None;
    rule.effect = NativeEffect::ResponseHeaderDate(
        serde_json::from_value(serde_json::json!({
            "header":"content-disposition", "parameter":"filename", "format":"%Y-%m-%d"
        }))
        .unwrap(),
    );
    let compiled = compile_native(&rule).unwrap();
    let NativeEffect::ResponseHeaderDate(effect) = &compiled.rule.effect else {
        unreachable!()
    };
    assert_eq!(effect.timezone, "+00:00");
}

#[test]
fn native_relative_times_accept_omitted_offsets_but_absolute_windows_require_them() {
    for format in [TimestampFormat::Iso8601Naive, TimestampFormat::SqlDatetime] {
        let mut time = NativeTime {
            format,
            relation: super::super::TimeRelation::PreserveOffset,
            anchor: super::super::TimeAnchor::DependencyRequestStart,
            utc_offset: None,
            clock_group: None,
            clock_scope: Default::default(),
        };
        validate_time(&time).unwrap();
        time.relation = super::super::TimeRelation::RequestWindow;
        assert!(validate_time(&time).is_err());
        time.utc_offset = Some("+08:00".into());
        validate_time(&time).unwrap();
        time.format = TimestampFormat::UnixSeconds;
        assert!(validate_time(&time).is_err());
    }
}

#[test]
fn integer_identity_cannot_advertise_an_unimplemented_cross_resource_reference() {
    let mut rule = path_rule();
    let NativeEffect::Identity(effect) = &mut rule.effect else {
        unreachable!()
    };
    effect.value_type = IdentityType::Integer;
    effect.format = None;
    effect.references[0].contract.resource.endpoint.host = "another-resource.test".into();
    let error = compile_native(&rule).unwrap_err();
    assert!(format!("{error:#}").contains("cross-resource integer references"));
}

#[test]
fn domains_keep_capture_and_ownership_separate_from_payload_comparison() {
    let mut rule = path_rule();
    rule.selector = NativeMatch::default();
    rule.effect = NativeEffect::CaptureHttp(CaptureHttpEffect {
        source_revision: format!("sha256:{}", "a".repeat(64)),
        case_paths: vec!["/tasks/*".into()],
    });
    assert_eq!(compile_native(&rule).unwrap().domain, NativeDomain::Capture);
    assert!(native_field_claims(&rule).is_empty());
    rule.selector.api = Some("GET /tasks/*".into());
    assert!(compile_native(&rule).is_err());
}
