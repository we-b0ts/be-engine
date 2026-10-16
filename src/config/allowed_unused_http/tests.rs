use super::*;

#[test]
fn unbounded_unused_hosts_cannot_mutate_a_unified_policy() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join(".traffic-e2e");
    fs::create_dir(&directory).unwrap();
    let project = directory.join("project.yaml");
    let rules = directory.join("policy.yaml");
    fs::write(
        &project,
        "project: {policy: .traffic-e2e/policy.yaml}\nrecorder: {}\n",
    )
    .unwrap();
    let original = crate::config::native_policy::empty_policy().unwrap();
    fs::write(&rules, &original).unwrap();
    let error = plan_allowed_unused_http_hosts(AllowedUnusedHttpHostFeedback {
        project_config_path: project,
        rules_path: rules.clone(),
        hosts: vec!["service.test".into()],
    })
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Source-proven process-owned HTTP selector")
    );
    assert_eq!(fs::read_to_string(rules).unwrap(), original);
}

#[test]
fn noncanonical_hosts_are_rejected_before_any_policy_change() {
    for host in [
        "https://example.com",
        "example.com:443",
        "*.example.com",
        "Example.com",
    ] {
        assert!(normalize_host(host).is_err());
    }
}
