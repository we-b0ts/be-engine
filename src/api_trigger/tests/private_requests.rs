use super::*;
use crate::interaction::model::{InputTranscript, Protocol};

fn managed_fixture(command: &str) -> Fixture {
    let mut fixture = Fixture::new(command);
    let project = fixture._temp.path();
    let local = project.join(".traffic-e2e/local");
    fs::create_dir_all(&local).unwrap();
    crate::platform::encryption_key::load_or_create(project).unwrap();
    let root = local.join("artifacts/recordings/run");
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    fs::rename(&fixture.root, &root).unwrap();
    fixture.root = root;
    fixture.origin = fixture.root.join("apis/jobs/origin");
    fixture.victim = fixture.root.join("apis/items/victim");
    fixture.write_report(command);
    fixture
}

fn protect(path: &Path, uri: &str) -> Vec<u8> {
    let mut request: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    request["uri"] = uri.into();
    request["interaction"] = serde_json::to_value(InputTranscript::new(
        Protocol::Sse,
        crate::InteractionPolicy::default(),
    ))
    .unwrap();
    crate::interaction::private::protect_request(&mut request, path).unwrap();
    let bytes = serde_json::to_vec(&request).unwrap();
    fs::write(path, &bytes).unwrap();
    bytes
}

#[test]
fn protected_stream_request_keeps_api_origin_policy_and_evidence_immutable() {
    let fixture = managed_fixture("DEL");
    let path = fixture.origin.join("request.json");
    let encrypted = protect(&path, "/jobs?token=private-stream-token");
    assert!(!String::from_utf8_lossy(&encrypted).contains("private-stream-token"));
    assert!(!String::from_utf8_lossy(&encrypted).contains("background"));

    let rules = fixture.rules("DEL");
    let cold = load(&fixture.root, &rules).unwrap();
    assert_eq!(cold.witnesses.len(), 1);
    let warm = load(&fixture.root, &rules).unwrap();
    assert!(warm.cache_reused);
    assert_eq!(warm.witnesses.len(), 1);
    assert_eq!(fixture.plan("DEL").report().matched_case_ids, ["victim"]);
    assert_eq!(fs::read(&path).unwrap(), encrypted);
}

#[test]
fn protected_stream_query_retains_same_resource_mutation_restriction() {
    let fixture = managed_fixture("DEL");
    protect(&fixture.origin.join("request.json"), "/jobs");
    let path = fixture.victim.join("request.json");
    let encrypted = protect(&path, "/items?job_id=12");
    assert!(!String::from_utf8_lossy(&encrypted).contains("job_id=12"));
    assert!(
        load(&fixture.root, &fixture.rules("DEL"))
            .unwrap()
            .witnesses
            .is_empty()
    );
    assert_eq!(fs::read(&path).unwrap(), encrypted);
}
