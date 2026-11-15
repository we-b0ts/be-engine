use super::*;

#[test]
fn catalog_features_control_the_complete_installation_set() {
    let codecs = build_codecs().unwrap();
    let policies = build_policies().unwrap();
    let mut protocols = traffic_protocol::ProviderRegistry::default();
    install_protocols(&mut protocols, traffic_protocol::ProtocolId::new).unwrap();
    for (name, installed) in [
        ("http", cfg!(feature = "protocol-http")),
        ("mysql", cfg!(feature = "protocol-mysql")),
        ("redis", cfg!(feature = "protocol-redis")),
        ("fixture-rpc", cfg!(feature = "protocol-fixture")),
    ] {
        assert_eq!(
            protocols
                .provider(traffic_protocol::ProtocolId::new(name))
                .is_ok(),
            installed
        );
    }
    for (id, installed) in [
        ("json", cfg!(feature = "codec-json")),
        ("scalar", cfg!(feature = "codec-json")),
        ("protobuf", cfg!(feature = "codec-protobuf")),
        ("string", cfg!(feature = "codec-string")),
        ("bytes", cfg!(feature = "codec-bytes")),
    ] {
        assert_eq!(
            codecs.descriptors().any(|descriptor| descriptor.id == id),
            installed
        );
    }
    for (id, installed) in [
        ("unordered", cfg!(feature = "policy-unordered")),
        (
            "unordered-joined-string",
            cfg!(feature = "policy-unordered"),
        ),
        ("duration", cfg!(feature = "policy-time")),
        ("time", cfg!(feature = "policy-time")),
        ("identity", cfg!(feature = "policy-identity")),
        ("documents", cfg!(feature = "policy-response-rewrite")),
    ] {
        assert_eq!(
            policies.descriptors().any(|descriptor| descriptor.id == id),
            installed
        );
    }
    assert_eq!(
        policies.supports("unordered", traffic_policy::PolicyAction::Compare),
        cfg!(feature = "policy-unordered")
    );
    assert_eq!(
        policies.supports("unordered", traffic_policy::PolicyAction::Analyze),
        cfg!(feature = "policy-unordered")
    );
    assert!(
        codecs
            .prepare("missing-codec", &traffic_value::Value::Null)
            .is_err()
    );
    assert!(
        policies
            .prepare("missing-policy", &traffic_value::Value::Null)
            .is_err()
    );
}
