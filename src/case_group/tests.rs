use tempfile::tempdir;

use super::*;

const CONFIG: &str = r#"[http_gateway]
enabled = true

[[http_gateway.rules]]
name = "record-api"
path_prefixes = ["/api"]
# BEGIN AI-MANAGED CASE PATH PATTERNS
# source_revision = "old"
case_path_patterns = [
]
# END AI-MANAGED CASE PATH PATTERNS
headers = {}

[recording]
access_policy = "unrestricted"
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
        rule: None,
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
    let config = temporary.path().join("recorder.toml");
    fs::write(&config, CONFIG).unwrap();
    let mut first_options = options(
        &source,
        &first,
        &output,
        "/api/huaweiyun/loadbalancers/get/:id",
        Some("/api/huaweiyun/loadbalancers/get/*"),
    );
    first_options.recorder_config = Some(config.clone());
    first_options.rule = Some("record-api".to_string());

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
        fs::read_to_string(&config)
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
fn mixed_route_directory_is_rejected() {
    let temporary = tempdir().unwrap();
    let source = temporary.path().join("cases");
    let group = source.join("mixed");
    write_case(&source, "mixed", "case-a", "GET", "/api/widgets/one");
    write_case(&source, "mixed", "case-b", "POST", "/api/widgets/two");

    let error = ensure_case_group(options(
        &source,
        &group,
        &temporary.path().join("case-groups.json"),
        "/api/widgets/:id",
        Some("/api/widgets/*"),
    ))
    .unwrap_err();

    assert!(error.to_string().contains("mixed-route directory"));
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
