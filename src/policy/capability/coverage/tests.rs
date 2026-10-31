use super::*;

#[test]
fn json_time_and_identity_have_the_same_installed_dependency_carriers() {
    for (protocol, slot) in [
        (ProtocolKind::Http, SlotKind::Body),
        (ProtocolKind::Redis, SlotKind::Value),
        (ProtocolKind::Memcached, SlotKind::Value),
    ] {
        for capability in [CapabilityId::RelativeTime, CapabilityId::Identity] {
            value_capability_support(
                ValueCoordinate {
                    protocol,
                    role: ProtocolRole::Dependency,
                    surface: Surface::DependencyRequest,
                    slot,
                    codec: CodecKind::Json,
                },
                capability,
            )
            .require()
            .unwrap();
        }
    }
}

#[test]
fn direct_mysql_value_bindings_require_a_real_live_executor() {
    for (surface, slot) in [
        (Surface::DependencyRequest, SlotKind::SqlValue),
        (Surface::DependencyResponse, SlotKind::SqlColumn),
    ] {
        for codec in [CodecKind::Json, CodecKind::Scalar, CodecKind::Protobuf] {
            let error = value_capability_support(
                ValueCoordinate {
                    protocol: ProtocolKind::Mysql,
                    role: ProtocolRole::Dependency,
                    surface,
                    slot,
                    codec,
                },
                CapabilityId::RelativeTime,
            )
            .require()
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("direct MySQL value-rule execution is not installed")
            );
        }
    }
    let native = NativeRule {
        id: "native-sql".into(),
        selector: crate::policy::native::NativeMatch {
            resource: Some(
                serde_yaml::from_str("protocol: mysql\nendpoint: db.test:3306\ndatabase: app")
                    .unwrap(),
            ),
            ..Default::default()
        },
        effect: NativeEffect::MysqlValues(crate::policy::native::MysqlValuesEffect {
            params: Default::default(),
            values: Default::default(),
        }),
        proof: None,
        when: None,
    };
    let plan = validate_native_coverage(&native).unwrap();
    assert_eq!(plan.protocol, Some(ProtocolKind::Mysql));
    assert_eq!(plan.kind, RuleKind::MysqlValues);
}
#[test]
fn unsupported_cells_are_explicit_instead_of_claiming_protocol_equivalence() {
    let mut query = ValueCoordinate {
        protocol: ProtocolKind::Redis,
        role: ProtocolRole::Dependency,
        surface: Surface::DependencyRequest,
        slot: SlotKind::Value,
        codec: CodecKind::Protobuf,
    };
    assert!(
        value_capability_support(query, CapabilityId::Identity)
            .require()
            .unwrap_err()
            .to_string()
            .contains("Protobuf identity")
    );
    value_capability_support(query, CapabilityId::RelativeTime)
        .require()
        .unwrap();
    query.codec = CodecKind::Scalar;
    assert!(
        value_capability_support(query, CapabilityId::Unordered)
            .require()
            .is_err()
    );
    query.codec = CodecKind::Json;
    assert!(
        value_capability_support(query, CapabilityId::RebaseTime)
            .require()
            .is_err()
    );
    for protocol in [ProtocolKind::Motan, ProtocolKind::Kafka] {
        query.protocol = protocol;
        assert!(
            value_capability_support(query, CapabilityId::RelativeTime)
                .require()
                .unwrap_err()
                .to_string()
                .contains("adapter is not installed")
        );
    }
    query.protocol = ProtocolKind::Mysql;
    assert!(
        value_capability_support(query, CapabilityId::Identity)
            .require()
            .is_err(),
        "SQL cannot silently use a key/value slot"
    );
}
#[test]
fn native_state_capture_and_attribution_never_masquerade_as_value_rules() {
    for (effect, kind, owner) in [
        (
            NativeEffect::RedisAppendStream,
            RuleKind::RedisAppendStream,
            ExecutionOwner::RedisState,
        ),
        (
            NativeEffect::RedisReadObservation,
            RuleKind::RedisReadObservation,
            ExecutionOwner::RedisState,
        ),
    ] {
        assert_eq!(native_kind_owner(&effect), (kind, owner));
        let plan = validate_native_coverage(&NativeRule {
            id: "native".into(),
            selector: Default::default(),
            effect,
            proof: None,
            when: None,
        })
        .unwrap();
        assert_eq!(plan.protocol, Some(ProtocolKind::Redis));
        assert!(plan.codec.is_none());
        assert!(plan.evidence.native_delivery);
    }
}

#[test]
fn an_actual_motan_primary_cannot_inherit_an_http_body_value_plan() {
    let rule: Rule = serde_yaml::from_str(
        r#"id: elapsed
surface: api.response
match: {api: GET /requests}
slot: body
codec: json
contract:
  /elapsed: {kind: duration, unit: seconds}
proof: {source: 'clock.py:elapsed', fact: 'Source stores elapsed request seconds'}
"#,
    )
    .unwrap();
    let plan = validate_rule_coverage(&rule).unwrap();
    validate_actual_protocol(&plan, ProtocolKind::Http, ProtocolRole::Primary).unwrap();
    let error =
        validate_actual_protocol(&plan, ProtocolKind::Motan, ProtocolRole::Primary).unwrap_err();
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("protocol=motan"));
    assert!(diagnostic.contains("adapter is not installed"));
    assert!(validate_actual_protocol(&plan, ProtocolKind::Http, ProtocolRole::Dependency).is_err());
    let native = NativeRule {
        id: "native".into(),
        selector: Default::default(),
        effect: NativeEffect::RedisAppendStream,
        proof: None,
        when: None,
    };
    let native = validate_native_coverage(&native).unwrap();
    // This generic check must not reinterpret a stateful operator as a value
    // plan; its native owner independently validates protocol and lifecycle.
    validate_actual_protocol(&native, ProtocolKind::Redis, ProtocolRole::Dependency).unwrap();
}
