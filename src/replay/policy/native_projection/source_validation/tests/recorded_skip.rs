//! Source-only checks against the original preserved-key and session fixtures.
use super::*;
use crate::policy::native::{IdentityCapture, PolicyRule};
use sha2::{Digest, Sha256};

#[test]
#[ignore = "requires TRAFFIC_E2E_SKIP_PROJECT and its original completed recording"]
fn recorded_skip_source_contracts_validate_preserved_keys_and_independent_session_tokens() {
    let root = std::path::PathBuf::from(std::env::var_os("TRAFFIC_E2E_SKIP_PROJECT").unwrap());
    let recording = root.join(".traffic-e2e/local/artifacts/recordings/20261016030056/apis");
    let mut document = crate::policy::parse_policy(
        &crate::recorder::test_io::read_to_string_sync(root.join(".traffic-e2e/policy.yaml"))
            .unwrap(),
    )
    .unwrap();
    document.rules.retain(|rule| {
        matches!(
            rule.id(),
            "attachment-upload-storage-key" | "attachment-upload-storage-key-multipart-init"
        )
    });
    for rule in &mut document.rules {
        let PolicyRule::Native(rule) = rule else {
            unreachable!()
        };
        let NativeEffect::Identity(effect) = &mut rule.effect else {
            unreachable!()
        };
        let IdentityCapture::HttpPath { segment } = &mut effect.capture else {
            unreachable!()
        };
        let field = &mut segment.fields.get_mut("created_at").unwrap().contract;
        let mut declaration = serde_json::to_value(&*field).unwrap();
        let fields = declaration.as_object_mut().unwrap();
        fields.remove("mode");
        fields.remove("timezone");
        *field = serde_json::from_value(declaration).unwrap();
    }
    assert_eq!(document.rules.len(), 2);
    let mut cases = Vec::new();
    let mut inputs = Vec::new();
    for (api, prefixes) in [
        ("api-attachments-wildcard", vec![""]),
        ("api-auth-wework-sessions", vec![""]),
    ] {
        for entry in std::fs::read_dir(recording.join(api)).unwrap() {
            let dir = entry.unwrap().path();
            let id = dir.file_name().unwrap().to_str().unwrap().to_owned();
            if !dir.is_dir() || !prefixes.iter().any(|prefix| id.starts_with(prefix)) {
                continue;
            }
            let path = dir.join("dependencies.jsonl");
            let bytes = std::fs::read(&path).unwrap();
            inputs.push((path, format!("{:x}", Sha256::digest(&bytes))));
            let events = bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice::<Value>(line).unwrap())
                .collect::<Vec<_>>();
            let request =
                serde_json::from_slice::<Value>(&std::fs::read(dir.join("request.json")).unwrap())
                    .unwrap();
            if api == "api-auth-wework-sessions" {
                let event = events
                    .iter()
                    .find(|event| event["command"] == "SET")
                    .unwrap();
                let rule = json!({"id":"wework-session-json","match":{"api":"POST /api/auth/wework/sessions",
                    "resource":{"protocol":"redis","endpoint":format!("{}:{}",event["target_host"].as_str().unwrap(),event["target_port"]),
                        "database":event["database"],"username":event["username"]},
                    "key":{"kind":"affix","prefix":"wework_auth_session:"}},
                    "effect":{"kind":"redis_sequence","key":{"kind":"capture","template":"wework_auth_session:{value}","format":{"kind":"uuid_v4"}},
                    "commands":[{"operation":"SET","arguments":{"1":{"kind":"json","fields":{
                        "/poll_token":{"kind":"random","format":"base64url","length":43},
                        "/created_at":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"},
                        "/expires_at":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"}
                    }}}}]},"proof":{"source":"app/api/endpoints/wework_auth.py:308-333","fact":"Source creates a uuid4 key, an independent token_urlsafe(32), and creation/expiry clocks before SET EX 300"}});
                let proposed = crate::policy::parse_policy(
                    &json!({"format":"traffic-policy/v3","rules":[rule]}).to_string(),
                )
                .unwrap();
                document.rules.extend(proposed.rules);
            }
            cases.push((id, dir, request, events));
        }
    }
    assert!(cases.len() >= 4);
    let policy = crate::policy::compile_policy(&document).unwrap();
    let selected = policy
        .native
        .iter()
        .map(|rule| rule.rule.id.clone())
        .collect();
    let cases = cases
        .iter()
        .map(|(id, dir, request, events)| NativeSourceCase {
            id,
            dir,
            request,
            events,
        })
        .collect::<Vec<_>>();
    let checked = validate_native_source_dependencies(&policy, &selected, &root, &cases).unwrap();
    assert_eq!(checked.rules["wework-session-json"], 1);
    assert!(checked.rules["attachment-upload-storage-key"] >= 3);
    for (path, digest) in inputs {
        assert_eq!(
            format!("{:x}", Sha256::digest(std::fs::read(path).unwrap())),
            digest
        );
    }
    println!(
        "original Source contracts validated: {:?}; independent Target Replay remains required",
        checked.rules
    );
}
