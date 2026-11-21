use super::*;

fn configured() -> AppConfig {
    serde_yaml::from_str("dns_mock: {enabled: true}\ntcp_gateway: {enabled: true}\nupstream_routes:\n- host: api.team.svc.cluster.local\n  via:\n    type: kubernetes_port_forward\n    namespace: team\n    service: api\n").unwrap()
}

#[test]
fn routes_need_no_ports_and_round_trip_with_existing_defaults() {
    let mut config = configured();
    config.validate().unwrap();
    config.upstream_routes[0].host = "API.TEAM.SVC.CLUSTER.LOCAL.".into();
    config.validate().unwrap();
    let round_trip: AppConfig =
        serde_yaml::from_str(&serde_yaml::to_string(&config).unwrap()).unwrap();
    round_trip.validate().unwrap();
    assert_eq!(
        round_trip.kubernetes.kubectl_binary,
        PathBuf::from("kubectl")
    );
}

#[test]
fn malformed_or_conflicting_routes_reject_before_startup() {
    for host in [
        "127.0.0.1",
        "*.svc.cluster.local",
        "api:8100",
        "api",
        " api.team.local",
        "api..team.local",
    ] {
        let mut config = configured();
        config.upstream_routes[0].host = host.into();
        assert!(config.validate().is_err(), "{host}");
    }
    let mut config = configured();
    config
        .upstream_routes
        .push(config.upstream_routes[0].clone());
    config.upstream_routes[1].host = "API.TEAM.SVC.CLUSTER.LOCAL.".into();
    assert!(config.validate().is_err());
    let mut config = configured();
    config.dns_mock.hosts.insert(
        "API.TEAM.SVC.CLUSTER.LOCAL.".into(),
        vec![std::net::Ipv4Addr::LOCALHOST],
    );
    assert!(config.validate().is_err());
    let mut config = configured();
    config.dns_mock.enabled = false;
    assert!(config.validate().is_err());
    let mut config = configured();
    config
        .dns_mock
        .bypass_domains
        .push(".svc.cluster.local".into());
    assert!(config.validate().is_err());
}

#[test]
fn unsupported_port_fields_are_not_silently_ignored() {
    let config = serde_yaml::to_string(&configured()).unwrap();
    for addition in ["  port: 8100\n", "  service_port: 8100\n"] {
        assert!(
            serde_yaml::from_str::<AppConfig>(
                &config.replace("  via:", &format!("{addition}  via:"))
            )
            .is_err()
        );
    }
}
