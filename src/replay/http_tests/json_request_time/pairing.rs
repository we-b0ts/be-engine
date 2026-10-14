//! Multiple request bodies at one endpoint must pair before time validation.
use super::*;

const QUERIES: [&str; 3] = ["first-expression", "second-expression", "third-expression"];

fn query_body(query: &str, end: i64) -> Value {
    let mut value = body(end);
    value["query"] = json!(query);
    value
}

struct Fixture {
    _temp: tempfile::TempDir,
    case: PathBuf,
    policy: PathBuf,
    report: PathBuf,
    original: Vec<u8>,
}

impl Fixture {
    async fn capture(actual: Vec<Value>) -> Self {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let local = root.join(".traffic-e2e/local");
        let key = std::env::var(crate::request_headers::ENCRYPTION_KEY_ENV)
            .unwrap_or_else(|_| STANDARD.encode([7u8; 32]));
        let key_path = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(key_path, key).unwrap();
        let case = local.join("recordings/run/case");
        write_http_case(
            &case,
            "http",
            "api.example.test",
            "/query",
            &body(1_700_000_000).to_string(),
            "recorded-result",
        )
        .await;
        let dependencies = case.join("dependencies.jsonl");
        let template: Value =
            serde_json::from_slice(&std::fs::read(&dependencies).unwrap()).unwrap();
        let mut original = Vec::new();
        for query in QUERIES {
            let mut event = template.clone();
            event["id"] = json!(uuid::Uuid::new_v4());
            event["request_started_at"] = json!("2023-11-14T22:13:20.125Z");
            event["request_headers"] =
                json!({"content-type":["application/json"],"authorization":["Bearer secret"]});
            event["request_body"] = body_capture(&query_body(query, 1_700_000_000).to_string());
            event["response_body"] = body_capture(query);
            event["response_headers"]["content-length"] = json!([query.len().to_string()]);
            original.extend(serde_json::to_vec(&event).unwrap());
            original.push(b'\n');
        }
        std::fs::write(&dependencies, &original).unwrap();
        std::fs::write(
            case.join("request.json"),
            r#"{"method":"POST","uri":"/windows/1","timestamp":"2023-11-14T22:00:00Z"}"#,
        )
        .unwrap();
        std::fs::write(case.join("expected-response.json"), "{}").unwrap();
        let policy = root.join(".traffic-e2e/verification.yaml");
        std::fs::write(
            &policy,
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        let (addr, runtime, task) =
            spawn_http_replay_with_policy(&case, vec![], Some(policy.clone()), None).await;
        runtime
            .state
            .lock()
            .await
            .replay_policy
            .as_ref()
            .unwrap()
            .request_contracts
            .request_begin("case")
            .unwrap();
        for body in actual {
            assert_eq!(
                send(addr, "/query", body.to_string(), "Bearer secret").await,
                StatusCode::BAD_GATEWAY
            );
        }
        let report = root.join("replay.json");
        {
            let mut state = runtime.state.lock().await;
            state.finalized_at = Some(Utc::now());
            std::fs::write(
                &report,
                serde_json::to_vec(&state.snapshot_report()).unwrap(),
            )
            .unwrap();
        }
        task.abort();
        Self {
            _temp: temp,
            case,
            policy,
            report,
            original,
        }
    }

    fn plan(&self) -> Result<crate::GeneratedValueRulePlan> {
        plan_dependency_request_rule(DependencyRequestRuleFeedback {
            policy_path: self.policy.clone(),
            rule: rule(),
            replay_report: self.report.clone(),
        })
    }
}

#[tokio::test]
async fn json_time_planner_pairs_nine_candidates_and_fresh_replay_consumes_each_response_once() {
    let now = Utc::now().timestamp();
    let fixture = Fixture::capture(
        QUERIES
            .into_iter()
            .rev()
            .map(|query| query_body(query, now))
            .collect(),
    )
    .await;
    let report: Value = serde_json::from_slice(&std::fs::read(&fixture.report).unwrap()).unwrap();
    assert_eq!(
        report["replay_policy"]["request_contract_candidates"]
            .as_array()
            .unwrap()
            .len(),
        9
    );
    let plan = fixture.plan().unwrap();
    assert_eq!(plan.report().matching_cases, 1);
    assert!(plan.apply().unwrap().requires_fresh_replay);
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&fixture.case, vec![], Some(fixture.policy.clone()), None)
            .await;
    for query in QUERIES.into_iter().rev() {
        let (status, response) = send_response(
            addr,
            "/query",
            query_body(query, Utc::now().timestamp()).to_string(),
            "Bearer secret",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response.as_ref(), query.as_bytes());
    }
    {
        let state = runtime.state.lock().await;
        assert!(!state.snapshot_report().is_dirty());
        let policy = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(policy.dependency_rules[0].matches, 3);
        assert_eq!(policy.dependency_rules[0].time_validations, 6);
    }
    assert_eq!(
        send(
            addr,
            "/query",
            query_body(QUERIES[0], Utc::now().timestamp()).to_string(),
            "Bearer secret",
        )
        .await,
        StatusCode::BAD_GATEWAY
    );
    task.abort();
    assert_eq!(
        std::fs::read(fixture.case.join("dependencies.jsonl")).unwrap(),
        fixture.original
    );
}

#[tokio::test]
async fn json_time_planner_rejects_invalid_times_even_after_a_valid_pair() {
    for invalid in ["stale", "relationship", "numeric-type", "missing"] {
        let now = Utc::now().timestamp();
        let mut body = query_body(QUERIES[1], now);
        match invalid {
            "stale" => body = query_body(QUERIES[1], now - 30),
            "relationship" => body["start"] = json!(now - 299),
            "numeric-type" => body["start"] = json!((now - 300) as f64),
            "missing" => {
                body.as_object_mut().unwrap().remove("start");
            }
            _ => unreachable!(),
        }
        let fixture = Fixture::capture(vec![query_body(QUERIES[0], now), body]).await;
        let policy = std::fs::read(&fixture.policy).unwrap();
        assert!(fixture.plan().is_err(), "{invalid}");
        assert_eq!(std::fs::read(&fixture.policy).unwrap(), policy);
    }
}

#[tokio::test]
async fn json_time_planner_requires_at_least_one_pair_with_matching_stable_fields() {
    for field in ["query", "step", "ordered", "extra"] {
        let mut actual = query_body(QUERIES[0], Utc::now().timestamp());
        actual[field] = match field {
            "ordered" => json!([2, 1]),
            "extra" => json!(1),
            _ => json!("changed"),
        };
        let fixture = Fixture::capture(vec![actual]).await;
        assert!(fixture.plan().is_err(), "{field}");
    }
}
