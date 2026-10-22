//! Complete Source traces must prove each declared read after its write.
use super::*;

fn rule() -> Value {
    json!({"id":"block","match":{"api":"POST /tasks","resource":resource(),"operation":"SET","key":{"kind":"affix","prefix":"current:"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
            "references":[{"resource":resource()}],"read_back":[{"operation":"GET","write_operation":"SET","argument_index":1}]},"proof":proof()})
}

fn events() -> Vec<Value> {
    let mut set = redis("SET", &["current:7", "old"], 1);
    set["response_kind"] = json!("simple_string");
    set["response"]["data"] = json!("+OK\r\n");
    let mut get = redis("GET", &["current:7"], 2);
    get["response_kind"] = json!("bulk_string");
    get["response"]["data"] = json!("$3\r\nold\r\n");
    vec![set, get, redis("APPEND", &["content:old", "x"], 3)]
}

#[test]
fn source_read_back_preflight_requires_a_complete_causal_positive_read_witness() {
    let policy = compile(vec![rule()]);
    let trace = events();
    assert!(check(&policy, &trace).is_ok());
    let mut missing = trace.clone();
    missing.remove(1);
    assert!(check(&policy, &missing).is_err());
    let mut wrong = trace.clone();
    wrong[1]["response"]["data"] = json!("$5\r\nother\r\n");
    assert!(check(&policy, &wrong).is_err());
    let mut failed = trace.clone();
    failed[0]["response_kind"] = json!("error");
    failed[0]["response"]["data"] = json!("-ERR write rejected\r\n");
    assert!(check(&policy, &failed).is_err());
    let mut no_read = trace;
    no_read[1]["response_kind"] = json!("null");
    no_read[1]["response"]["data"] = json!("$-1\r\n");
    assert!(check(&policy, &no_read).is_err());
}

#[test]
#[ignore = "requires TRAFFIC_E2E_READ_BACK_PROJECT and TRAFFIC_E2E_READ_BACK_RECORDING"]
fn recorded_read_back_source_policy_validates_without_changing_project_or_recordings() {
    use crate::policy::native::{Proven, RedisReadBack};
    let root = PathBuf::from(std::env::var_os("TRAFFIC_E2E_READ_BACK_PROJECT").unwrap());
    let recording = PathBuf::from(std::env::var_os("TRAFFIC_E2E_READ_BACK_RECORDING").unwrap());
    let policy_path = root.join(".traffic-e2e/policy.yaml");
    let policy_bytes = std::fs::read(&policy_path).unwrap();
    let mut document =
        crate::policy::parse_policy(std::str::from_utf8(&policy_bytes).unwrap()).unwrap();
    document.rules.retain(|r| {
        matches!(
            r.id(),
            "responses-create-text-block-current-id"
                | "responses-create-thinking-block-current-id"
                | "responses-task-streaming-status-times"
        )
    });
    assert_eq!(document.rules.len(), 3);
    let selected = document
        .rules
        .iter()
        .map(|r| r.id().to_owned())
        .collect::<BTreeSet<_>>();
    for rule in &mut document.rules {
        let crate::policy::PolicyRule::Native(rule) = rule else {
            panic!()
        };
        let fields = if rule.id == "responses-task-streaming-status-times" {
            vec!["/started_at".into()]
        } else {
            vec![]
        };
        let entry = Proven {
            contract: RedisReadBack {
                state_epochs: None,
                operation: "GET".into(),
                write_operation: "SET".into(),
                argument_index: 1,
                json_pointers: fields,
            },
            proof: rule.proof.clone(),
        };
        match &mut rule.effect {
            NativeEffect::Identity(effect) => effect.read_back.push(entry),
            NativeEffect::RedisSequence(effect) => effect.read_back.push(entry),
            _ => panic!(),
        }
    }
    let policy = crate::policy::compile_policy(&document).unwrap();
    let mut entries = std::fs::read_dir(&recording)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.join("dependencies.jsonl").is_file())
        .collect::<Vec<_>>();
    entries.sort();
    assert!(!entries.is_empty());
    let mut inventory = Vec::new();
    let mut originals = Vec::new();
    for directory in entries {
        let path = directory.join("dependencies.jsonl");
        let bytes = std::fs::read(&path).unwrap();
        let id = directory.file_name().unwrap().to_str().unwrap().to_owned();
        let request: Value =
            serde_json::from_slice(&std::fs::read(directory.join("request.json")).unwrap())
                .unwrap();
        let events = bytes
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(serde_json::from_slice)
            .collect::<std::result::Result<Vec<Value>, _>>()
            .unwrap();
        inventory.push((id, directory, request, events));
        originals.push((path, bytes));
    }
    let cases = inventory
        .iter()
        .map(|(id, dir, request, events)| NativeSourceCase {
            id,
            dir,
            request,
            events,
        })
        .collect::<Vec<_>>();
    validate_native_source_dependencies(&policy, &selected, &root, &cases)
        .unwrap_or_else(|error| panic!("complete Source inventory: {error:#}"));
    for (path, bytes) in originals {
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    assert_eq!(std::fs::read(&policy_path).unwrap(), policy_bytes);
}
