use super::*;
use crate::policy::{Database, Endpoint, Protocol, Resource};
use crate::value_contract::plan::IndexRequirement as I;

fn request(operation: Option<&str>) -> ResourcePreparationRequest<'_> {
    ResourcePreparationRequest {
        operation,
        value_slot: None,
        semantic_links: false,
    }
}

#[test]
fn native_versions_are_bound_to_the_dependency_role_and_exact_protocol() {
    use NativeProtocolVersion as V;
    for (protocol, versions) in [
        (ProtocolKind::Http, &[V::Http][..]),
        (ProtocolKind::Redis, &[V::RedisResp2, V::RedisResp3][..]),
        (ProtocolKind::Mysql, &[V::MysqlClassic][..]),
        (
            ProtocolKind::Memcached,
            &[V::MemcachedText, V::MemcachedBinary][..],
        ),
        (ProtocolKind::Motan, &[V::Motan1, V::Motan2][..]),
        (ProtocolKind::Kafka, &[V::Kafka][..]),
    ] {
        let contract = ResourceProvider::for_protocol(protocol).contract();
        assert_eq!(contract.protocol, protocol);
        assert_eq!(contract.role, ProtocolRole::Dependency);
        assert_eq!(contract.native_versions, versions);
        for version in versions {
            contract.validate_version(*version).unwrap();
        }
        let other = if protocol == ProtocolKind::Http {
            V::MysqlClassic
        } else {
            V::Http
        };
        assert!(contract.validate_version(other).is_err());
    }
}

#[test]
fn resource_binding_preserves_native_qualifiers_and_rejects_cross_protocol_identity() {
    let redis = ResourceProvider::Redis
        .bind_resource(NativeResource::Redis {
            host: "cache.test",
            port: 6379,
            database: Some(3),
            username: Some("service"),
        })
        .unwrap();
    assert!(matches!(
        redis.native,
        NativeResource::Redis {
            database: Some(3),
            username: Some("service"),
            ..
        }
    ));
    assert!(ResourceProvider::Mysql.bind_resource(redis.native).is_err());
    let motan = ResourceProvider::Motan
        .bind_resource(NativeResource::Motan {
            host: "rpc.test",
            port: 8002,
            group: Some("payments"),
        })
        .unwrap();
    assert_eq!(motan.endpoint(), ("rpc.test", 8002));
    assert!(matches!(
        motan.native,
        NativeResource::Motan {
            group: Some("payments"),
            ..
        }
    ));
}

#[test]
fn policy_resource_dimensions_cannot_silently_disappear() {
    let mut resource = Resource {
        protocol: Protocol::Redis,
        endpoint: Endpoint {
            host: "resource.test".into(),
            port: 6379,
        },
        database: Some(Database::Index(3)),
        username: Some("service".into()),
    };
    assert!(matches!(
        NativeResource::from_policy(&resource).unwrap(),
        NativeResource::Redis {
            database: Some(3),
            username: Some("service"),
            ..
        }
    ));
    resource.database = Some(Database::Name("3".into()));
    assert!(NativeResource::from_policy(&resource).is_err());
    resource.protocol = Protocol::Mysql;
    resource.database = Some(Database::Index(3));
    assert!(NativeResource::from_policy(&resource).is_err());
    resource.database = Some(Database::Name("catalogue".into()));
    assert!(matches!(
        NativeResource::from_policy(&resource).unwrap(),
        NativeResource::Mysql {
            database: Some("catalogue"),
            ..
        }
    ));
    for protocol in [Protocol::Http, Protocol::Memcached] {
        resource.protocol = protocol;
        assert!(NativeResource::from_policy(&resource).is_err());
    }
}

#[test]
fn preparation_does_not_invent_http_lanes_or_generic_kafka_ordering() {
    for (provider, lookup, ordered) in [
        (ResourceProvider::Http, LookupPreparation::Indexed, false),
        (ResourceProvider::Redis, LookupPreparation::Indexed, true),
        (ResourceProvider::Mysql, LookupPreparation::Indexed, true),
        (
            ResourceProvider::Memcached,
            LookupPreparation::ExistingNative,
            true,
        ),
        (
            ResourceProvider::Motan,
            LookupPreparation::ExistingNative,
            true,
        ),
        (
            ResourceProvider::Kafka,
            LookupPreparation::ExistingNative,
            false,
        ),
    ] {
        let prepared = provider.prepare(request(None)).unwrap();
        assert_eq!(prepared.lookup, lookup);
        assert!(prepared.indexes.required.contains(&I::Scope));
        assert!(prepared.indexes.required.contains(&I::EndpointOperation));
        assert_eq!(
            prepared.indexes.required.contains(&I::SessionOrder),
            ordered
        );
        assert!(!prepared.indexes.required.contains(&I::TypedSlot));
    }
}

#[test]
fn sql_selector_preparation_only_applies_to_actual_sql_operations() {
    for operation in [None, Some("COM_QUERY"), Some("COM_STMT_EXECUTE")] {
        assert_eq!(
            ResourceProvider::Mysql
                .prepare(request(operation))
                .unwrap()
                .selector,
            SelectorPreparation::SqlTemplate
        );
    }
    for (provider, operation) in [
        (ResourceProvider::Mysql, "COM_INIT_DB"),
        (ResourceProvider::Redis, "SET"),
        (ResourceProvider::Http, "MOTAN"),
        (ResourceProvider::Motan, "echo"),
        (ResourceProvider::Kafka, "produce"),
    ] {
        let prepared = provider.prepare(request(Some(operation))).unwrap();
        assert_eq!(prepared.operation.symbol(), Some(operation));
        assert_eq!(prepared.selector, SelectorPreparation::NativeOperation);
    }
    for operation in ["mg", "SASL_AUTH", "unknown"] {
        assert!(
            ResourceProvider::Memcached
                .prepare(request(Some(operation)))
                .is_err()
        );
    }
}

#[test]
fn strict_native_support_does_not_imply_typed_payload_or_primary_slot_support() {
    for provider in [ResourceProvider::Motan, ResourceProvider::Kafka] {
        provider.prepare(request(None)).unwrap();
        for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
            let error = provider
                .prepare(ResourcePreparationRequest {
                    value_slot: Some((surface, SlotKind::Body)),
                    ..request(None)
                })
                .unwrap_err();
            assert!(error.to_string().contains("adapter is not installed"));
        }
    }
    let prepared = ResourceProvider::Redis
        .prepare(ResourcePreparationRequest {
            value_slot: Some((Surface::DependencyRequest, SlotKind::Value)),
            semantic_links: true,
            ..request(Some("SET"))
        })
        .unwrap();
    assert!(prepared.indexes.required.contains(&I::TypedSlot));
    assert!(prepared.indexes.required.contains(&I::SemanticLink));
    assert!(
        ResourceProvider::Http
            .value_slot(Surface::ApiResponse, SlotKind::Body)
            .require()
            .is_err()
    );
    assert!(
        ResourceProvider::Mysql
            .value_slot(Surface::DependencyResponse, SlotKind::SqlValue)
            .require()
            .is_err()
    );
}

#[test]
fn compiled_native_rules_consume_provider_requirements_with_global_value_formats() {
    let policy = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /elapsed: {kind: duration, formats: [seconds]}
rules:
  - id: transport
    match:
      resource: {protocol: http, endpoint: 'api.test:8080'}
      operation: POST
      path: /send
    effect:
      kind: http_request
      query:
        nonce: {kind: uuid_v4}
    proof: {source: 'app/client.rs:1', fact: 'Source generates the native query nonce'}
"#,
    )
    .unwrap();
    assert!(policy.rules.is_empty(), "field formats remain global");
    assert!(
        policy
            .global_json
            .as_ref()
            .unwrap()
            .fields
            .contains_key("/elapsed")
    );
    let requirements = &policy.native[0].execution_plan.indexes.required;
    assert!(requirements.contains(&I::EndpointOperation));
    assert!(requirements.contains(&I::TypedSlot));
    assert!(!requirements.contains(&I::SessionOrder));
}

#[test]
fn native_http_sharing_cannot_reintroduce_a_connection_lane_requirement() {
    let rule = crate::policy::NativeRule {
        id: "share-http".into(),
        selector: Default::default(),
        effect: crate::policy::NativeEffect::FiniteSharing(
            crate::policy::native::FiniteSharingEffect::Http,
        ),
        proof: None,
        when: None,
    };
    let prepared = crate::policy::validate_native_coverage(&rule).unwrap();
    assert_eq!(prepared.protocol, Some(ProtocolKind::Http));
    assert!(!prepared.indexes.required.contains(&I::SessionOrder));
    let mut redis = rule;
    redis.effect = crate::policy::NativeEffect::FiniteSharing(
        crate::policy::native::FiniteSharingEffect::Redis { hash_field: None },
    );
    let prepared = crate::policy::validate_native_coverage(&redis).unwrap();
    assert!(prepared.indexes.required.contains(&I::SessionOrder));
}
