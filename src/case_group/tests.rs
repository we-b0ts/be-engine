use tempfile::tempdir;

use super::*;

const CONFIG: &str = r#"version: 14
project:
  recording:
    source_traffic_policy: source-traffic-policy.yaml
recorder:
  http_gateway:
    enabled: true
    rules:
    - name: http-rule
      path_prefixes: [/api]
      headers: {}
  recording:
    access_policy: unrestricted
"#;

fn write_case(root: &Path, group: &str, case_id: &str, method: &str, uri: &str) -> PathBuf {
    let directory = root.join(group).join(case_id);
    write_case_files(&directory, method, uri);
    directory
}

fn write_case_files(directory: &Path, method: &str, uri: &str) {
    fs::create_dir_all(directory).unwrap();
    fs::write(
        directory.join("request.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "method": method,
            "uri": uri,
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(directory.join("expected-response.json"), b"{}\n").unwrap();
}

fn write_recording_case(
    source: &Path,
    member: &str,
    case_id: &str,
    method: &str,
    uri: &str,
    api_pattern: &str,
) -> PathBuf {
    let directory = source.join("apis").join(member).join(case_id);
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("request.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "method": method,
            "uri": uri,
            "matched_rule": "http-rule",
            "api_pattern": api_pattern,
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(directory.join("expected-response.json"), b"{}\n").unwrap();
    directory
}

fn write_case_at(
    root: &Path,
    group: &str,
    case_id: &str,
    method: &str,
    uri: &str,
    timestamp: &str,
) -> PathBuf {
    let directory = root.join(group).join(case_id);
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("request.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "timestamp": timestamp,
            "method": method,
            "uri": uri,
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(directory.join("expected-response.json"), b"{}\n").unwrap();
    directory
}

fn options(
    case_source: &Path,
    case_dir: &Path,
    output: &Path,
    source_route: &str,
    pattern: Option<&str>,
) -> CaseGroupOptions {
    CaseGroupOptions {
        case_source: case_source.to_path_buf(),
        case_dir: case_dir.to_path_buf(),
        method: "get".to_string(),
        source_route: source_route.to_string(),
        pattern: pattern.map(str::to_string),
        source_revision: "source-abc123".to_string(),
        output: output.to_path_buf(),
        recorder_config: None,
    }
}

#[test]
fn dynamic_group_collects_sibling_directories_applies_pattern_and_is_idempotent() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    let first = source.join("get-alpha");
    let second = source.join("get-beta");
    write_case(
        &source,
        "get-alpha",
        "case-a",
        "GET",
        "/api/huaweiyun/loadbalancers/get/alpha?detail=true",
    );
    write_case(
        &source,
        "get-beta",
        "case-b",
        "GET",
        "/api/huaweiyun/loadbalancers/get/beta",
    );
    let output = temporary.path().join("reports/case-groups.json");
    let config = temporary.path().join("project.yaml");
    fs::write(&config, CONFIG).unwrap();
    fs::write(
        temporary.path().join("source-traffic-policy.yaml"),
        crate::config::SourceTrafficPolicyConfig::empty()
            .render()
            .unwrap(),
    )
    .unwrap();
    let mut first_options = options(
        &source,
        &first,
        &output,
        "/api/huaweiyun/loadbalancers/get/:id",
        Some("/api/huaweiyun/loadbalancers/get/*"),
    );
    first_options.recorder_config = Some(config.clone());

    let created = ensure_case_group(first_options.clone()).unwrap();

    assert_eq!(created.status, CaseGroupStatus::Created);
    assert_eq!(created.case_ids, vec!["case-a", "case-b"]);
    assert_eq!(created.member_dirs, vec![first.clone(), second.clone()]);
    assert!(created.group_dir.is_none());
    assert_eq!(
        created.manifest,
        fs::canonicalize(output.parent().unwrap())
            .unwrap()
            .join("case-groups.json")
    );
    assert_eq!(
        created.pattern_outcome.status,
        PatternOutcomeStatus::Applied
    );
    let persisted: serde_json::Value =
        serde_json::from_slice(&fs::read(&created.report_path).unwrap()).unwrap();
    assert_eq!(persisted["groups"][0]["status"], "created");
    assert_eq!(
        persisted["groups"][0]["manifest"],
        created.manifest.display().to_string()
    );
    assert!(
        fs::read_to_string(temporary.path().join("source-traffic-policy.yaml"))
            .unwrap()
            .contains("/api/huaweiyun/loadbalancers/get/*")
    );
    assert!(!source.join("case-groups.json").exists());

    first_options.case_dir = second;
    let repeated = ensure_case_group(first_options).unwrap();
    assert_eq!(repeated.status, CaseGroupStatus::AlreadyGrouped);
    assert_eq!(repeated.group_id, created.group_id);
    assert_eq!(repeated.case_inventory_id, created.case_inventory_id);
}

#[test]
fn replay_api_selection_collects_cases_across_member_directories() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    write_case(&source, "get-alpha", "case-a", "GET", "/api/widgets/alpha");
    write_case(&source, "get-beta", "case-b", "GET", "/api/widgets/beta");
    write_case(&source, "get-other", "case-other", "GET", "/api/other");

    let selected =
        resolve_recording_api_case_ids(&source, &["GET /api/widgets/*".parse().unwrap()]).unwrap();

    assert_eq!(selected, ["case-a", "case-b"]);
}

#[test]
fn replay_api_selection_rejects_overlapping_selectors() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    write_case(&source, "get-alpha", "case-a", "GET", "/api/widgets/alpha");

    let error = resolve_recording_api_case_ids(
        &source,
        &[
            "GET /api/widgets/*".parse().unwrap(),
            "GET /api/widgets/alpha".parse().unwrap(),
        ],
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("overlapping replay API selectors"));
    assert!(error.contains("case-a"));
}

#[test]
fn catch_all_group_collects_cases_at_different_remaining_depths() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    let pod = source.join("get-pod");
    let service = source.join("get-service");
    write_case(
        &source,
        "get-pod",
        "case-pod",
        "GET",
        "/api/k8s/v1/namespaces/default/pods/nginx",
    );
    write_case(
        &source,
        "get-service",
        "case-service",
        "GET",
        "/api/k8s/v1/namespaces/default/services",
    );

    let result = ensure_case_group(options(
        &source,
        &pod,
        &temporary.path().join("case-groups.json"),
        "/api/k8s/v1/namespaces/*",
        Some("/api/k8s/v1/namespaces/**"),
    ))
    .unwrap();

    assert_eq!(result.status, CaseGroupStatus::Created);
    assert_eq!(result.case_ids, vec!["case-pod", "case-service"]);
    assert_eq!(result.member_dirs, vec![pod, service]);
    assert_eq!(result.pattern.as_deref(), Some("/api/k8s/v1/namespaces/**"));
}

#[test]
fn static_route_uses_the_existing_directory_as_the_group() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    let group = source.join("list");
    write_case(&source, "list", "case-a", "GET", "/api/widgets/list?page=1");
    write_case(&source, "list", "case-b", "GET", "/api/widgets/list?page=2");
    let output = temporary.path().join("case-groups.json");

    let result =
        ensure_case_group(options(&source, &group, &output, "/api/widgets/list", None)).unwrap();

    assert_eq!(result.status, CaseGroupStatus::AlreadyCanonical);
    assert_eq!(result.group_dir, Some(group));
    assert_eq!(result.case_ids, vec!["case-a", "case-b"]);
    assert_eq!(
        result.pattern_outcome.status,
        PatternOutcomeStatus::NotRequiredStatic
    );
}

#[test]
fn recording_run_preserves_each_api_member() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("recording-run");
    let show_member = source.join("apis/2-users-show.json");
    let batch_member = source.join("apis/2-users-show_batch.json");
    write_recording_case(
        &source,
        "2-users-show.json",
        "case-show",
        "GET",
        "/2/users/show.json?uid=1",
        "/2/users/show.json",
    );
    write_recording_case(
        &source,
        "2-users-show_batch.json",
        "case-batch",
        "GET",
        "/2/users/show_batch.json?uids=1,2",
        "/2/users/show_batch.json",
    );

    let show_api = "GET /2/users/show.json".parse().unwrap();
    assert_eq!(
        resolve_recording_api_member(&source, &show_api).unwrap(),
        show_member
    );

    let result = ensure_case_group(options(
        &source,
        &batch_member,
        &temporary.path().join("case-groups.json"),
        "/2/users/show_batch.json",
        None,
    ))
    .unwrap();

    assert_eq!(result.status, CaseGroupStatus::AlreadyCanonical);
    assert_eq!(result.group_dir, Some(batch_member.clone()));
    assert_eq!(result.member_dirs, vec![batch_member]);
    assert_eq!(result.case_ids, vec!["case-batch"]);
}

#[test]
fn http_and_motan_share_the_apis_root_without_mixed_layout() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("recording-run");
    let http_member = source.join("apis/http-users");
    let motan_member = source.join("apis/AlchemyRpcService-getConfig-hash");
    write_recording_case(
        &source,
        "http-users",
        "case-http",
        "GET",
        "/api/users/1",
        "/api/users/*",
    );
    write_recording_case(
        &source,
        "AlchemyRpcService-getConfig-hash",
        "case-motan",
        "MOTAN",
        "/rpc/AlchemyRpcService-getConfig-hash",
        "/rpc/AlchemyRpcService-getConfig-hash",
    );

    assert_eq!(
        resolve_recording_api_member(&source, &"GET /api/users/*".parse().unwrap()).unwrap(),
        http_member
    );
    assert_eq!(
        resolve_recording_api_member(
            &source,
            &"MOTAN /rpc/AlchemyRpcService-getConfig-hash"
                .parse()
                .unwrap(),
        )
        .unwrap(),
        motan_member
    );
}

#[test]
fn cases_are_ordered_by_recording_timestamp_instead_of_case_id() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    let group = source.join("list");
    write_case_at(
        &source,
        "list",
        "case-a",
        "GET",
        "/api/widgets/list?page=2",
        "2026-07-24T02:00:02Z",
    );
    write_case_at(
        &source,
        "list",
        "case-z",
        "GET",
        "/api/widgets/list?page=1",
        "2026-07-24T02:00:01Z",
    );

    let result = ensure_case_group(options(
        &source,
        &group,
        &temporary.path().join("case-groups.json"),
        "/api/widgets/list",
        None,
    ))
    .unwrap();

    assert_eq!(result.case_ids, vec!["case-z", "case-a"]);
}

#[test]
fn a_single_case_directory_can_be_its_own_case_source() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("case-root");
    write_case_files(&source, "GET", "/api/widgets/list");

    let result = ensure_case_group(options(
        &source,
        &source,
        &temporary.path().join("case-groups.json"),
        "/api/widgets/list",
        None,
    ))
    .unwrap();

    assert_eq!(result.status, CaseGroupStatus::AlreadyCanonical);
    assert_eq!(result.group_dir, Some(source));
    assert_eq!(result.case_ids, vec!["case-root"]);
}

#[test]
fn ignored_artifact_directory_cannot_be_used_as_a_case_source() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join(".partial");
    write_case(&source, "list", "case-a", "GET", "/api/widgets/list");

    let error = ensure_case_group(options(
        &source,
        &source.join("list"),
        &temporary.path().join("case-groups.json"),
        "/api/widgets/list",
        None,
    ))
    .unwrap_err();

    assert!(error.to_string().contains("ignored or incomplete artifact"));
}

#[test]
fn methods_share_a_directory_with_disjoint_manifest_membership() {
    for pattern in [None, Some("/api/subscriptions/*")] {
        let temporary = tempdir().unwrap();
        let source = temporary.path().join("cases");
        let member = source.join("apis/api-subscriptions-230827");
        write_recording_case(
            &source,
            "api-subscriptions-230827",
            "put-case",
            "PUT",
            "/api/subscriptions/230827",
            "/api/subscriptions/230827",
        );
        write_recording_case(
            &source,
            "api-subscriptions-230827",
            "delete-case",
            "DELETE",
            "/api/subscriptions/230827",
            "/api/subscriptions/230827",
        );
        let output = temporary.path().join("case-groups.json");
        let route = if pattern.is_some() {
            "/api/subscriptions/:id"
        } else {
            "/api/subscriptions/230827"
        };
        for (method, id) in [("PUT", "put-case"), ("DELETE", "delete-case")] {
            let mut request = options(&source, &member, &output, route, pattern);
            request.method = method.into();
            let created = ensure_case_group(request.clone()).unwrap();
            assert_eq!(created.status, CaseGroupStatus::Created);
            assert!(created.group_dir.is_none());
            assert_eq!(created.case_ids, vec![id]);
            assert_eq!(
                ensure_case_group(request).unwrap().status,
                CaseGroupStatus::AlreadyGrouped
            );
        }
        let inventory = load_complete_case_group_inventory(&output, &source).unwrap();
        assert_eq!(inventory.groups.len(), 2);
        assert_eq!(
            inventory
                .groups
                .iter()
                .map(|g| g.cases.len())
                .sum::<usize>(),
            2
        );
    }
}

#[test]
fn pattern_must_follow_the_dynamic_segments_in_the_source_route() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    let group = source.join("get-alpha");
    write_case(&source, "get-alpha", "case-a", "GET", "/api/widgets/alpha");

    let error = ensure_case_group(options(
        &source,
        &group,
        &temporary.path().join("case-groups.json"),
        "/api/widgets/list",
        Some("/api/widgets/*"),
    ))
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("does not match dynamic source route")
    );
}

#[test]
fn catch_all_must_be_final_and_replace_a_dynamic_source_segment() {
    assert!(validate_pattern("/api/namespaces/**").is_ok());
    assert!(validate_pattern("/api/**/pods").is_err());
    assert!(
        validate_pattern_against_source_route("/api/namespaces/**", "/api/namespaces/*").is_ok()
    );
    assert!(
        validate_pattern_against_source_route("/api/namespaces/**", "/api/namespaces/list")
            .is_err()
    );
}

#[test]
fn changed_case_inventory_requires_a_reviewed_new_index() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    let first = source.join("get-alpha");
    write_case(&source, "get-alpha", "case-a", "GET", "/api/widgets/alpha");
    let output = temporary.path().join("case-groups.json");
    let ensure = options(
        &source,
        &first,
        &output,
        "/api/widgets/:id",
        Some("/api/widgets/*"),
    );
    ensure_case_group(ensure.clone()).unwrap();
    write_case(&source, "get-beta", "case-b", "GET", "/api/widgets/beta");

    let error = ensure_case_group(ensure).unwrap_err();

    assert!(error.to_string().contains("inventory") && error.to_string().contains("stale"));
}

#[test]
fn changed_source_revision_is_rejected() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    let group = source.join("list");
    write_case(&source, "list", "case-a", "GET", "/api/widgets/list");
    let output = temporary.path().join("case-groups.json");
    let ensure = options(&source, &group, &output, "/api/widgets/list", None);
    ensure_case_group(ensure.clone()).unwrap();
    let mut changed = ensure;
    changed.source_revision = "source-def456".to_string();

    let error = ensure_case_group(changed).unwrap_err();

    assert!(error.to_string().contains("source revision changed"));
}

#[test]
fn duplicate_case_ids_are_rejected() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    write_case(&source, "first", "duplicate", "GET", "/api/widgets/alpha");
    write_case(&source, "second", "duplicate", "GET", "/api/widgets/beta");

    let error = ensure_case_group(options(
        &source,
        &source.join("first"),
        &temporary.path().join("case-groups.json"),
        "/api/widgets/:id",
        Some("/api/widgets/*"),
    ))
    .unwrap_err();

    assert!(error.to_string().contains("duplicate case id"));
}

#[test]
fn group_index_cannot_be_written_inside_case_source() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    write_case(&source, "list", "case-a", "GET", "/api/widgets/list");

    let error = ensure_case_group(options(
        &source,
        &source.join("list"),
        &source.join("case-groups.json"),
        "/api/widgets/list",
        None,
    ))
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("outside the canonical case source")
    );
}

#[test]
fn complete_inventory_requires_every_published_case_grouped_once() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    let list = source.join("list");
    let create = source.join("create");
    write_case(&source, "list", "case-list", "GET", "/api/widgets");
    write_case(&source, "create", "case-create", "POST", "/api/widgets");
    let output = temporary.path().join("case-groups.json");

    ensure_case_group(options(&source, &list, &output, "/api/widgets", None)).unwrap();
    let error = load_complete_case_group_inventory(&output, &source).unwrap_err();
    assert!(error.to_string().contains("does not cover published cases"));

    let mut create_options = options(&source, &create, &output, "/api/widgets", None);
    create_options.method = "post".to_string();
    ensure_case_group(create_options).unwrap();
    let inventory = load_complete_case_group_inventory(&output, &source).unwrap();
    assert_eq!(inventory.groups.len(), 2);
    assert_eq!(
        inventory
            .groups
            .iter()
            .map(|group| group.cases.len())
            .sum::<usize>(),
        2
    );
}

#[test]
fn target_root_relative_index_survives_moving_the_target() {
    let temporary = tempdir().unwrap();
    let original_root = temporary.path().join("original-target");
    let moved_root = temporary.path().join("moved-target");
    let source = original_root.join("recordings/run");
    let member = source.join("health");
    write_case(&source, "health", "case-health", "GET", "/health");
    let output = original_root.join("runtime/run/case-groups.json");

    super::ensure_case_group_with_target_root(
        options(&source, &member, &output, "/health", None),
        &original_root,
    )
    .unwrap();

    let persisted: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(persisted["version"], 2);
    assert_eq!(persisted["path_anchor"], "target_root");
    assert_eq!(persisted["case_source"], "recordings/run");
    assert_eq!(
        persisted["groups"][0]["member_dirs"][0],
        "recordings/run/health"
    );
    assert_eq!(
        persisted["groups"][0]["manifest"],
        "runtime/run/case-groups.json"
    );

    fs::rename(&original_root, &moved_root).unwrap();
    let inventory = load_complete_case_group_inventory(
        &moved_root.join("runtime/run/case-groups.json"),
        &moved_root.join("recordings/run"),
    )
    .unwrap();

    assert_eq!(inventory.groups.len(), 1);
    assert_eq!(inventory.groups[0].cases.len(), 1);
    assert_eq!(
        inventory.groups[0].cases[0].case_dir,
        moved_root.join("recordings/run/health/case-health")
    );
}

#[test]
fn absolute_index_is_not_silently_rebased_to_another_case_source() {
    let temporary = tempdir().unwrap();
    let original_source = temporary.path().join("original-cases");
    let original_member = original_source.join("health");
    write_case(&original_source, "health", "case-health", "GET", "/health");
    let original_output = temporary.path().join("original-index/case-groups.json");
    ensure_case_group(options(
        &original_source,
        &original_member,
        &original_output,
        "/health",
        None,
    ))
    .unwrap();

    let copied_source = temporary.path().join("copied-cases");
    write_case(&copied_source, "health", "case-health", "GET", "/health");
    let copied_output = temporary.path().join("copied-index/case-groups.json");
    fs::create_dir_all(copied_output.parent().unwrap()).unwrap();
    fs::copy(original_output, &copied_output).unwrap();

    let error = load_complete_case_group_inventory(&copied_output, &copied_source).unwrap_err();
    assert!(error.to_string().contains("different case source"));
}

#[test]
fn unrelated_valid_raw_paths_do_not_block_a_canonical_dynamic_group() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    let docx = write_recording_case(
        &source,
        "docx",
        "case-docx",
        "POST",
        "/api/tasks/7/export/docx/download-url?message_ids=1%2C2",
        "/api/tasks/*/export/docx/download-url",
    );
    let slash = write_recording_case(
        &source,
        "auth",
        "case-auth",
        "POST",
        "/api/v1/auth/tokens/",
        "/api/v1/auth/tokens/",
    );
    let repeated = write_recording_case(
        &source,
        "other",
        "case-other",
        "GET",
        "/api//other",
        "/api//other",
    );
    let original =
        [&docx, &slash, &repeated].map(|case| fs::read(case.join("request.json")).unwrap());
    let output = temporary.path().join("reports/case-groups.json");
    let mut request = options(
        &source,
        docx.parent().unwrap(),
        &output,
        "/api/tasks/{task_id}/export/docx/download-url",
        Some("/api/tasks/*/export/docx/download-url"),
    );
    request.method = "POST".into();
    let group = ensure_case_group(request.clone()).unwrap();
    assert_eq!(group.status, CaseGroupStatus::Created);
    assert_eq!(group.case_ids, ["case-docx"]);
    assert_eq!(
        ensure_case_group(request).unwrap().status,
        CaseGroupStatus::AlreadyGrouped
    );
    let published = discover_published_cases(&source).unwrap();
    assert_eq!(published.len(), 3);
    assert_eq!(
        published
            .iter()
            .find(|case| case.id == "case-auth")
            .unwrap()
            .path,
        "/api/v1/auth/tokens/"
    );
    assert_eq!(
        published
            .iter()
            .find(|case| case.id == "case-other")
            .unwrap()
            .path,
        "/api//other"
    );
    assert!(
        load_complete_case_group_inventory(&output, &source).is_err(),
        "unselected raw paths remain part of full coverage"
    );
    for (case, bytes) in [&docx, &slash, &repeated].into_iter().zip(original) {
        assert_eq!(fs::read(case.join("request.json")).unwrap(), bytes);
    }
}

#[test]
fn recorded_trailing_slashes_never_alias_static_or_dynamic_group_membership() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    for (id, path) in [
        ("plain", "/api/items"),
        ("plain-slash", "/api/items/"),
        ("item", "/api/items/7"),
        ("item-slash", "/api/items/7/"),
    ] {
        write_recording_case(&source, "shared", id, "GET", path, path);
    }
    let member = source.join("apis/shared");
    let output = temporary.path().join("reports/case-groups.json");
    let plain = ensure_case_group(options(&source, &member, &output, "/api/items", None)).unwrap();
    assert_eq!(plain.case_ids, ["plain"]);
    let item = ensure_case_group(options(
        &source,
        &member,
        &output,
        "/api/items/{id}",
        Some("/api/items/*"),
    ))
    .unwrap();
    assert_eq!(item.case_ids, ["item"]);
    assert!(load_complete_case_group_inventory(&output, &source).is_err());
    for (route, expected) in [
        ("/api/items/", "plain-slash"),
        ("/api/items/7/", "item-slash"),
    ] {
        let literal = ensure_case_group(options(&source, &member, &output, route, None)).unwrap();
        assert_eq!(literal.case_ids, [expected]);
    }
    assert_eq!(
        load_complete_case_group_inventory(&output, &source)
            .unwrap()
            .groups
            .len(),
        4
    );
    for (route, pattern) in [
        ("/api/items/{id}", Some("/api/items/*/")),
        ("/api/items/{id}", Some("/api//items/*")),
    ] {
        assert!(
            ensure_case_group(options(
                &source,
                &member,
                &temporary.path().join("invalid/index.json"),
                route,
                pattern
            ))
            .is_err(),
            "canonical selectors stay strict: {route} {pattern:?}"
        );
    }
}

#[test]
fn discovery_still_rejects_invalid_recorded_http_paths() {
    for path in ["api/items", "/api/bad path", "/api/bad\npath"] {
        let temporary = tempdir().unwrap();
        write_case(temporary.path(), "member", "case", "GET", path);
        assert!(
            discover_published_cases(temporary.path()).is_err(),
            "{path:?}"
        );
    }
}

mod literal_paths;
