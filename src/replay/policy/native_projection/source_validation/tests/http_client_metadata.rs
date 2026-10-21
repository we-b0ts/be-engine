use super::*;

#[test]
fn client_metadata_requires_a_positive_source_witness_for_every_selected_header() {
    let rule = json!({"id":"sdk","match":{"api":"POST /tasks","resource":{"protocol":"http","endpoint":"client.test:8080"},"operation":"POST","path":"/responses"},
        "effect":{"kind":"http_client_metadata","headers":["x-stainless-lang","x-stainless-runtime"]},"proof":proof()});
    let policy = compile(vec![rule]);
    let event = json!({"event_type":"http_exchange","id":"source-http","scheme":"http","authority":"client.test:8080","method":"POST","uri":"/responses",
        "request_body":{"encoding":"utf8","data":"{}","truncated":false},"request_headers":{"X-Stainless-Lang":["python"],"x-stainless-runtime":["CPython"]},
        "response_status":200,"response_headers":{},"response_body":{"encoding":"utf8","data":"ok","truncated":false},"timestamp":"1970-01-01T00:16:41Z","request_started_at":"1970-01-01T00:16:40Z","duration_ms":1000,"outcome":"response","error":null});
    assert_eq!(
        check(&policy, std::slice::from_ref(&event)).unwrap().rules["sdk"],
        1
    );
    for value in [json!([]), json!([""]), json!(["<redacted>"]), Value::Null] {
        let mut missing = event.clone();
        if value.is_null() {
            missing["request_headers"]
                .as_object_mut()
                .unwrap()
                .remove("x-stainless-runtime");
        } else {
            missing["request_headers"]["x-stainless-runtime"] = value;
        }
        let error = check(&policy, &[missing]).err().unwrap().to_string();
        assert!(error.contains("x-stainless-runtime"), "{error}");
    }
    for (field, value) in [
        ("method", "GET"),
        ("uri", "/other"),
        ("authority", "other.test:8080"),
    ] {
        let mut unrelated = event.clone();
        unrelated[field] = value.into();
        assert!(check(&policy, &[unrelated]).is_err());
    }
}

#[test]
#[ignore = "requires TRAFFIC_E2E_HTTP_METADATA_PROJECT and TRAFFIC_E2E_HTTP_METADATA_POLICY with immutable recordings"]
fn client_metadata_recorded_source_contract_keeps_original_evidence() {
    let root = PathBuf::from(std::env::var_os("TRAFFIC_E2E_HTTP_METADATA_PROJECT").unwrap());
    let path = PathBuf::from(std::env::var_os("TRAFFIC_E2E_HTTP_METADATA_POLICY").unwrap());
    let policy =
        crate::policy::parse_and_compile_policy(&std::fs::read_to_string(path).unwrap()).unwrap();
    let api =
        root.join(".traffic-e2e/local/artifacts/recordings/20261020065443/apis/api-v1-responses");
    let selected = policy
        .native
        .iter()
        .filter(|rule| matches!(rule.rule.effect, NativeEffect::HttpClientMetadata(_)))
        .map(|rule| rule.rule.id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(selected.len(), 1);
    let mut owned = Vec::new();
    for id in [
        "e5c837d8-744f-4df2-9aaa-71e0cd64aa78",
        "df5d766e-242c-4b9b-9f83-49c79d882937",
        "42218e94-f10d-4469-821f-ffdbed795200",
    ] {
        let dir = api.join(id);
        let original = std::fs::read(dir.join("dependencies.jsonl")).unwrap();
        let events = original
            .split(|b| *b == b'\n')
            .filter(|v| !v.is_empty())
            .map(|v| serde_json::from_slice::<Value>(v).unwrap())
            .collect::<Vec<_>>();
        let request: Value =
            serde_json::from_slice(&std::fs::read(dir.join("request.json")).unwrap()).unwrap();
        owned.push((id, dir, request, events, original));
    }
    let cases = owned
        .iter()
        .map(|(id, dir, request, events, _)| NativeSourceCase {
            id,
            dir,
            request,
            events,
        })
        .collect::<Vec<_>>();
    let checked = validate_native_source_dependencies(&policy, &selected, &root, &cases).unwrap();
    assert_eq!(checked.rules[selected.iter().next().unwrap()], 3);
    for (_, dir, _, _, original) in &owned {
        assert_eq!(
            &std::fs::read(dir.join("dependencies.jsonl")).unwrap(),
            original
        );
    }
}
