use super::*;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("recordings");
    let project = temp.path().join("project.yaml");
    fs::write(&project, super::tests::CONFIG).unwrap();
    let mut policy = crate::config::SourceTrafficPolicyConfig::empty();
    policy.http.source_routes = vec![
        "GET /api/items/upload".into(),
        "GET /api/items/*".into(),
        "POST /api/items/*".into(),
    ]
    .try_into()
    .unwrap();
    fs::write(
        temp.path().join("source-traffic-policy.yaml"),
        policy.render().unwrap(),
    )
    .unwrap();
    let output = temp.path().join("groups.json");
    (temp, source, project, output)
}

#[test]
fn static_and_pattern_groups_are_disjoint_in_either_prepare_order() {
    for static_first in [true, false] {
        let (_temp, source, project, output) = fixture();
        let upload = source.join("static");
        let dynamic = source.join("dynamic");
        super::tests::write_case(&source, "static", "upload", "GET", "/api/items/upload");
        super::tests::write_case(&source, "dynamic", "get", "GET", "/api/items/7");
        super::tests::write_case(&source, "dynamic", "post", "POST", "/api/items/8");
        let mut options = [
            super::tests::options(&source, &upload, &output, "/api/items/upload", None),
            super::tests::options(
                &source,
                &dynamic,
                &output,
                "/api/items/:id",
                Some("/api/items/*"),
            ),
        ];
        if !static_first {
            options.reverse();
        }
        for mut option in options {
            option.recorder_config = Some(project.clone());
            ensure_case_group(option).unwrap();
        }
        let mut post = super::tests::options(
            &source,
            &dynamic,
            &output,
            "/api/items/:id",
            Some("/api/items/*"),
        );
        post.method = "POST".into();
        post.recorder_config = Some(project.clone());
        ensure_case_group(post).unwrap();
        let inventory = load_complete_case_group_inventory(&output, &source).unwrap();
        assert_eq!(inventory.groups.len(), 3);
        let mut ids = BTreeSet::new();
        for group in inventory.groups {
            assert_eq!(group.cases.len(), 1);
            assert!(ids.insert(group.cases[0].case_id.clone()));
            if group.pattern.is_some() {
                assert_ne!(group.cases[0].case_id, "upload");
            }
        }
        assert_eq!(ids.len(), 3);
    }
}

#[test]
fn mixed_api_directory_is_rejected_without_publishing_groups() {
    let (_temp, source, project, output) = fixture();
    super::tests::write_case(&source, "mixed", "upload", "GET", "/api/items/upload");
    super::tests::write_case(&source, "mixed", "detail", "GET", "/api/items/7");
    let mut option = super::tests::options(
        &source,
        &source.join("mixed"),
        &output,
        "/api/items/:id",
        Some("/api/items/*"),
    );
    option.recorder_config = Some(project);
    let error = ensure_case_group(option).unwrap_err();
    assert!(error.to_string().contains("multiple canonical APIs"));
    assert!(!output.exists());
}

#[test]
fn wildcard_seed_never_selects_a_registered_static_member() {
    let (_temp, source, project, _output) = fixture();
    // The static directory sorts before the dynamic one.
    super::tests::write_case(&source, "a-static", "upload", "GET", "/api/items/upload");
    super::tests::write_case(&source, "z-dynamic", "detail", "GET", "/api/items/7");
    let routes = crate::config::AppConfig::load(&project)
        .unwrap()
        .http_gateway
        .source_routes;
    let member =
        resolve_recording_api_seed_member(&source, &"GET /api/items/*".parse().unwrap(), &routes)
            .unwrap();
    assert_eq!(member, fs::canonicalize(source.join("z-dynamic")).unwrap());
    let selected = resolve_recording_api_case_ids_with_routes(
        &source,
        &["GET /api/items/*".parse().unwrap()],
        &routes,
    )
    .unwrap();
    assert_eq!(selected, ["detail"]);
}

#[test]
fn index_without_source_registration_cannot_authorize_replay() {
    let (_temp, source, _project, output) = fixture();
    super::tests::write_case(&source, "static", "upload", "GET", "/api/items/upload");
    let option = super::tests::options(
        &source,
        &source.join("static"),
        &output,
        "/api/items/upload",
        None,
    );
    ensure_case_group(option).unwrap();
    let mut index: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    index.as_object_mut().unwrap().remove("source_routes");
    fs::write(&output, serde_json::to_vec(&index).unwrap()).unwrap();
    assert!(
        load_complete_case_group_inventory(&output, &source)
            .unwrap_err()
            .to_string()
            .contains("no confirmed HTTP Source registration")
    );
}

#[test]
fn old_group_index_is_rejected_instead_of_running_legacy_selection() {
    let (_temp, source, _project, output) = fixture();
    super::tests::write_case(&source, "static", "upload", "GET", "/api/items/upload");
    let option = super::tests::options(
        &source,
        &source.join("static"),
        &output,
        "/api/items/upload",
        None,
    );
    ensure_case_group(option.clone()).unwrap();
    let original = fs::read(&output).unwrap();
    for version in [1, 2] {
        let mut old: serde_json::Value = serde_json::from_slice(&original).unwrap();
        old["version"] = version.into();
        fs::write(&output, serde_json::to_vec(&old).unwrap()).unwrap();
        let before = fs::read(&output).unwrap();
        assert!(
            ensure_case_group(option.clone())
                .unwrap_err()
                .to_string()
                .contains("unsupported group index version")
        );
        assert_eq!(fs::read(&output).unwrap(), before);
    }
}
