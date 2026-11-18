use super::super::*;
use crate::policy::{AsyncApiRules, AsyncHttpEnd, AsyncRedisPublishEnd};
use crate::protocols::recording::events::{HttpExchangeEvent, RedisExchangeEvent};
use crate::recorder::capture_body;
use hyper::Method;
use serde_json::{Value, json};

fn rule() -> AsyncApiRule {
    AsyncApiRule {
        when_response: BTreeMap::from([("/status".into(), json!("queued"))]),
        unless_response: BTreeMap::from([("/is_latest".into(), json!(true))]),
        end: vec![AsyncEnd::RedisPublish(AsyncRedisPublishEnd {
            when_response: Default::default(),
            operation: "PUBLISH".into(),
            channel: "socketio".into(),
            when_message: BTreeMap::from([
                ("/method".into(), json!("emit")),
                ("/event".into(), json!("chat:start")),
                ("/namespace".into(), json!("/chat")),
            ]),
            database: Some(2),
            endpoint: Some(Endpoint {
                host: "redis.test".into(),
                port: 6379,
            }),
        })],
        ..Default::default()
    }
}

fn scope() -> ResourceScope {
    ResourceScope::new(rule())
}

fn publication() -> RedisExchangeEvent {
    let RecorderEvent::RedisExchange(mut event) =
        crate::protocols::recording::async_api::tests::redis("PUBLISH", b"socketio")
    else {
        unreachable!()
    };
    event.args.push(capture_body(
        br#"{"method":"emit","event":"chat:start","namespace":"/chat","data":[{"task_id":10,"subtask_id":20}],"room":"task:10"}"#,
        4096,
    ));
    // Redis successfully accepts PUBLISH even with no current subscribers.
    event.response = capture_body(b":0\r\n", 4096);
    event
}

fn message(event: &mut RedisExchangeEvent, value: &Value) {
    event.args[1] = capture_body(&serde_json::to_vec(value).unwrap(), 4096);
}

fn business_completion(signal: Option<AsyncSignal>) -> bool {
    signal.is_some_and(|signal| signal.end_reason == AsyncEndReason::Resource)
}

fn assert_live_recorded(event: RedisExchangeEvent, expected: bool) {
    let event = RecorderEvent::RedisExchange(event);
    assert_eq!(business_completion(scope().observe(&event)), expected);
    let recorded = serde_json::to_value(event).unwrap();
    assert_eq!(
        business_completion(scope().observe_recorded(&recorded).unwrap()),
        expected
    );
}

#[test]
fn publication_requires_the_exact_channel_and_all_json_conditions() {
    assert_live_recorded(publication(), true);
    for (field, value) in [
        ("event", json!("task:created")),
        ("event", json!("chat:chunk")),
        ("event", json!("chat:done")),
        ("event", json!(null)),
        ("method", json!("callback")),
        ("namespace", json!("/other")),
    ] {
        let mut event = publication();
        let mut payload: Value = serde_json::from_slice(&decode(&event.args[1]).unwrap()).unwrap();
        payload[field] = value;
        message(&mut event, &payload);
        assert_live_recorded(event, false);
    }
    for channel in [b"other".as_slice(), b"SOCKETIO", b"socketio:other"] {
        let mut event = publication();
        event.args[0] = capture_body(channel, 4096);
        assert_live_recorded(event, false);
    }
    for bytes in [
        br#"{"method":"emit","event":"chat:start"}"#.as_slice(),
        br#"{"method":"emit","event":"chat:chunk","event":"chat:start","namespace":"/chat"}"#,
        br#"{"method":"emit","event":"chat:start","namespace":"/chat"} trailing"#,
        b"not json",
    ] {
        let mut event = publication();
        event.args[1] = capture_body(bytes, 4096);
        assert_live_recorded(event, false);
    }
}

#[test]
fn publication_requires_a_successful_complete_native_integer_reply_including_zero() {
    for reply in [b":0\r\n".as_slice(), b":1\r\n", b":17\r\n"] {
        let mut event = publication();
        event.response = capture_body(reply, 4096);
        assert_live_recorded(event, true);
    }
    for reply in [
        b":-1\r\n".as_slice(),
        b":0\r",
        b":0\r\n:1\r\n",
        b"+OK\r\n",
        b"-ERR failed\r\n",
        b"not RESP",
    ] {
        let mut event = publication();
        event.response = capture_body(reply, 4096);
        assert_live_recorded(event, false);
    }
    for outcome in [
        DependencyExchangeOutcome::NoResponse,
        DependencyExchangeOutcome::ClientTerminated,
    ] {
        let mut event = publication();
        event.outcome = outcome;
        assert_live_recorded(event, false);
    }
    for kind in ["error", "blob_error", "bulk_string", "other"] {
        let mut event = publication();
        event.response_kind = kind.into();
        assert_live_recorded(event, false);
    }
    let mut warning = publication();
    warning.parse_warnings.push("unsupported response".into());
    assert_live_recorded(warning, false);
}

#[test]
fn publication_requires_exact_arity_and_physical_resource_scope() {
    for command in ["SPUBLISH", "GET", "EVALSHA"] {
        let mut event = publication();
        event.command = command.into();
        // EVALSHA has no valid script key-count argument. The live matcher
        // still rejects it without parsing a different command's message.
        let event = RecorderEvent::RedisExchange(event);
        assert!(!business_completion(scope().observe(&event)));
        let recorded = scope().observe_recorded(&serde_json::to_value(event).unwrap());
        assert!(!recorded.is_ok_and(business_completion));
    }
    for extra in [false, true] {
        let mut event = publication();
        if extra {
            event.args.push(capture_body(b"extra", 4096));
        } else {
            event.args.pop();
        }
        assert_live_recorded(event, false);
    }
    let mut wrong_database = publication();
    wrong_database.database = 3;
    assert_live_recorded(wrong_database, false);
    let mut wrong_host = publication();
    wrong_host.target_host = "other.test".into();
    assert_live_recorded(wrong_host, false);
    let mut wrong_port = publication();
    wrong_port.target_port = 6380;
    assert_live_recorded(wrong_port, false);
    let mut mixed_case = publication();
    mixed_case.command = "pUbLiSh".into();
    mixed_case.target_host = "REDIS.test".into();
    assert_live_recorded(mixed_case, true);
}

#[test]
fn incomplete_or_corrupt_capture_can_never_supply_business_completion() {
    for index in 0..3 {
        for corruption in 0..4 {
            let mut event = publication();
            let body = match index {
                0 | 1 => &mut event.args[index],
                _ => &mut event.response,
            };
            match corruption {
                0 => body.truncated = true,
                1 => body.original_len += 1,
                2 => body.stored_len += 1,
                _ => {
                    body.encoding = "base64";
                    body.data = "not valid base64!".into();
                }
            }
            assert_live_recorded(event, false);
        }
    }
    let mut valid_base64 = publication();
    for body in valid_base64
        .args
        .iter_mut()
        .chain(std::iter::once(&mut valid_base64.response))
    {
        body.data = base64::engine::general_purpose::STANDARD.encode(decode(body).unwrap());
        body.encoding = "base64";
    }
    assert_live_recorded(valid_base64, true);
}

#[test]
fn historical_publication_without_complete_reply_or_warning_evidence_stays_unfinished() {
    for field in ["response", "parse_warnings"] {
        let mut event = serde_json::to_value(RecorderEvent::RedisExchange(publication())).unwrap();
        event.as_object_mut().unwrap().remove(field);
        assert!(!business_completion(
            scope().observe_recorded(&event).unwrap()
        ));
    }
}

fn submission() -> RecorderEvent {
    RecorderEvent::HttpExchange(HttpExchangeEvent {
        outcome: DependencyExchangeOutcome::Response,
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        request_started_at: chrono::Utc::now(),
        client_addr: None,
        scheme: "http".into(),
        method: "POST".into(),
        uri: "/submit".into(),
        authority: Some("executor.test".into()),
        request_headers: BTreeMap::new(),
        request_body: capture_body(b"{}", 100),
        response_status: Some(202),
        response_headers: Some(BTreeMap::new()),
        response_body: Some(capture_body(b"{}", 100)),
        response_stream: None,
        discovered_tcp_targets: Vec::new(),
        duration_ms: 10,
        error: None,
    })
}

#[test]
fn queued_rule_waits_past_the_old_http_end_and_retains_early_matching_publication() {
    let mut old = scope();
    old.rule.end = vec![AsyncEnd::Http(AsyncHttpEnd {
        method: "POST".into(),
        endpoint: Endpoint {
            host: "executor.test".into(),
            port: 80,
        },
        path: "/submit".into(),
        status_codes: vec![],
    })];
    assert!(business_completion(old.observe(&submission())));
    assert!(!business_completion(scope().observe(&submission())));
    assert!(!business_completion(
        scope()
            .observe_recorded(&serde_json::to_value(submission()).unwrap())
            .unwrap()
    ));
    for primary_first in [false, true] {
        let rules = BTreeMap::from([("POST /jobs".into(), AsyncApiRules(vec![rule()]))]);
        let selected =
            AsyncScope::for_primary(&rules, &Method::POST, &"/jobs".parse().unwrap(), b"{}")
                .unwrap();
        assert!(selected.observe(&submission()).is_none());
        if primary_first {
            assert!(
                selected
                    .select_response(Some(&json!({"status":"queued"})))
                    .1
                    .is_none()
            );
        }
        let mut other = publication();
        message(
            &mut other,
            &json!({"method":"emit","event":"task:created","namespace":"/chat"}),
        );
        assert!(
            selected
                .observe(&RecorderEvent::RedisExchange(other))
                .is_none()
        );
        let signal = selected.observe(&RecorderEvent::RedisExchange(publication()));
        if primary_first {
            assert!(business_completion(signal));
        } else {
            assert!(signal.is_none());
            assert!(business_completion(
                selected
                    .select_response(Some(&json!({"status":"queued"})))
                    .1
            ));
        }
    }
}

#[test]
#[ignore = "requires caller-supplied ASYNC_PUBLISH_* sealed Source witness inputs"]
fn external_sealed_queued_publish_is_a_source_terminal_witness() -> anyhow::Result<()> {
    use crate::dependency::observation::{
        MANIFEST_FILE, SCOPE_SCHEMA, ScopeIndex, ScopeKind, ScopeRecordLocation,
    };
    use crate::dependency_index::{FileStamp, recording};
    use anyhow::{Context, ensure};
    use std::{
        fs,
        io::{Read as _, Seek as _, SeekFrom},
        path::{Path, PathBuf},
    };

    let required = |name: &str| std::env::var(name).with_context(|| format!("missing {name}"));
    let source = PathBuf::from(required("ASYNC_PUBLISH_SOURCE")?);
    let case_id: uuid::Uuid = required("ASYNC_PUBLISH_CASE_ID")?.parse()?;
    let exchange_id: uuid::Uuid = required("ASYNC_PUBLISH_EXCHANGE_ID")?.parse()?;
    let policy_path = PathBuf::from(required("ASYNC_PUBLISH_POLICY_FILE")?);
    let baseline_path = PathBuf::from(required("ASYNC_PUBLISH_BASELINE_POLICY_FILE")?);
    let (root, manifest) = recording::manifest(&source)?;
    let root = fs::canonicalize(root)?;
    ensure!(
        manifest.capture_complete,
        "historical Source capture is incomplete"
    );
    recording::authenticate(&root)?;
    let input = manifest
        .inputs
        .iter()
        .find(|input| input.case_id == case_id && input.complete)
        .context("selected Case is not a complete sealed Source input")?;
    let directory = root.join(&input.path);
    ensure!(
        fs::canonicalize(&directory)?.starts_with(&root),
        "Case escapes recording"
    );

    let read_sealed = |path: &Path| -> anyhow::Result<Vec<u8>> {
        ensure!(
            fs::canonicalize(path)?.starts_with(&root),
            "evidence escapes recording"
        );
        let relative = path.strip_prefix(&root)?;
        let identity = manifest
            .files
            .iter()
            .find(|file| Path::new(&file.path) == relative)
            .context("Source witness file is not sealed")?;
        FileStamp::read_native(path)?;
        let bytes = fs::read(path)?;
        ensure!(
            bytes.len() as u64 == identity.length
                && crate::policy_evidence::digest(&bytes).trim_start_matches("sha256:")
                    == identity.sha256.trim_start_matches("sha256:"),
            "sealed Source witness changed"
        );
        Ok(bytes)
    };
    let scope_path = directory.join("dependency-scope.json");
    let unowned_path = root.join("indexes/unattributed-scope.json");
    let observation_path = directory.join("async-api-observation.json");
    let central = root.join("dependencies.jsonl");
    let paths = [
        root.join(MANIFEST_FILE),
        central.clone(),
        scope_path.clone(),
        unowned_path.clone(),
        observation_path.clone(),
        directory.join("request.json"),
        directory.join("expected-response.json"),
    ];
    let stamps = paths
        .iter()
        .map(|path| Ok((path.clone(), FileStamp::read_native(path)?)))
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
    let manifest_digest = crate::policy_evidence::digest(&fs::read(root.join(MANIFEST_FILE))?);
    let original: Value = serde_json::from_slice(&read_sealed(&observation_path)?)?;
    ensure!(
        original["end_reason"] == "resource" && original["event_type"] == "http_exchange",
        "selected historical Case did not end at an HTTP resource"
    );
    let request: Value = serde_json::from_slice(&read_sealed(&directory.join("request.json"))?)?;
    let response: Value =
        serde_json::from_slice(&read_sealed(&directory.join("expected-response.json"))?)?;
    let request_body = traffic_policy_schema::case_condition::request_body(&request)
        .context("Source request JSON absent")?;
    let response_body = traffic_policy_schema::case_condition::request_body(&response)
        .context("Source response JSON absent")?;
    let method: Method = request["method"]
        .as_str()
        .context("Source method absent")?
        .parse()?;
    let uri = request["uri"]
        .as_str()
        .context("Source URI absent")?
        .parse()?;
    let load_policy = |path: &Path| -> anyhow::Result<crate::policy::CompiledPolicy> {
        let proposed: serde_yaml::Value = serde_yaml::from_slice(&fs::read(path)?)?;
        let document = proposed.get("policy").unwrap_or(&proposed);
        crate::policy::parse_and_compile_policy(&serde_yaml::to_string(document)?)
    };
    let compiled = load_policy(&policy_path)?;
    let baseline_policy = load_policy(&baseline_path)?;
    let body = serde_json::to_vec(&request_body)?;
    let selected = AsyncScope::for_primary(&compiled.async_api, &method, &uri, &body)
        .context("Source input does not select proposed lifecycle")?;
    let baseline = AsyncScope::for_primary(&baseline_policy.async_api, &method, &uri, &body)
        .context("Source input does not select baseline lifecycle")?;
    ensure!(
        selected.select_response(Some(&response_body)).0
            && baseline.select_response(Some(&response_body)).0,
        "Source response selects no baseline or proposed scenario"
    );
    let scenario = selected.scenario_index().context("scenario absent")?;
    ensure!(
        baseline.api == selected.api
            && baseline.scenario_index() == Some(scenario)
            && original["scenario_index"].as_u64() == Some(scenario as u64),
        "baseline or proposal changed original scenario selection"
    );
    ensure!(
        matches!(
            baseline_policy.async_api[&baseline.api][scenario]
                .end
                .as_slice(),
            [AsyncEnd::Http(_)]
        ),
        "baseline scenario does not declare one HTTP terminal"
    );
    let ends = &compiled.async_api[&selected.api][scenario].end;
    ensure!(
        matches!(ends.as_slice(), [AsyncEnd::RedisPublish(_)]),
        "proposal did not replace the old HTTP end"
    );
    let case_scope: ScopeIndex = serde_json::from_slice(&read_sealed(&scope_path)?)?;
    ensure!(
        case_scope.schema == SCOPE_SCHEMA,
        "unsupported Case scope schema"
    );
    ensure!(
        matches!(case_scope.scope, ScopeKind::Case { case_id: id } if id == case_id),
        "Case scope has another owner"
    );
    ensure!(
        fs::canonicalize(directory.join(&case_scope.run_relpath))? == root,
        "Case scope points to another recording"
    );
    let unowned: ScopeIndex = serde_json::from_slice(&read_sealed(&unowned_path)?)?;
    ensure!(
        unowned.schema == SCOPE_SCHEMA,
        "unsupported unowned scope schema"
    );
    ensure!(
        matches!(unowned.scope, ScopeKind::Unattributed),
        "unowned scope has another kind"
    );
    ensure!(
        fs::canonicalize(root.join("indexes").join(&unowned.run_relpath))? == root,
        "unowned scope points to another recording"
    );
    let locations = case_scope
        .locations
        .iter()
        .chain(&unowned.locations)
        .filter(|location| location.exchange_id == exchange_id)
        .collect::<Vec<_>>();
    ensure!(
        locations.len() == 1,
        "publication UUID is absent or ambiguous in original scopes"
    );

    let mut ledger = fs::File::open(&central)?;
    let mut read_record = |location: &ScopeRecordLocation| -> anyhow::Result<Value> {
        ensure!(
            location.length > 0
                && location
                    .offset
                    .checked_add(location.length)
                    .is_some_and(|end| end <= stamps[&central].size),
            "invalid physical Source location"
        );
        ledger.seek(SeekFrom::Start(location.offset))?;
        let mut bytes = vec![0; usize::try_from(location.length)?];
        ledger.read_exact(&mut bytes)?;
        ensure!(
            crate::policy_evidence::digest(&bytes).trim_start_matches("sha256:")
                == location.sha256.trim_start_matches("sha256:"),
            "Source record checksum mismatch"
        );
        let event: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            event["capture"]["exchange_id"] == location.exchange_id.to_string(),
            "Source record UUID differs from scope identity"
        );
        Ok(event)
    };
    let publication = read_record(locations[0])?;
    ensure!(
        publication["event_type"] == "redis_exchange" && publication["command"] == "PUBLISH",
        "selected original occurrence is not PUBLISH"
    );
    let http_refs = original["completed_refs"]
        .as_array()
        .context("original completion refs absent")?
        .iter()
        .filter(|reference| reference["protocol"] == "http")
        .filter_map(|reference| reference["exchange_id"].as_str())
        .collect::<BTreeSet<_>>();
    let mut submissions = Vec::new();
    for location in &case_scope.locations {
        let event = read_record(location)?;
        if business_completion(baseline.observe_recorded(&event)?) {
            ensure!(
                event["event_type"] == "http_exchange"
                    && event["method"] == "POST"
                    && event["id"]
                        .as_str()
                        .is_some_and(|id| http_refs.contains(id)),
                "baseline terminal is not the original completed HTTP POST"
            );
            submissions.push(event);
        }
    }
    ensure!(
        submissions.len() == 1,
        "historical executor POST is not uniquely identifiable"
    );

    ensure!(
        !business_completion(selected.observe_recorded(&submissions[0])?),
        "old executor POST still ends the proposed lifecycle"
    );
    ensure!(
        business_completion(selected.observe_recorded(&publication)?),
        "original PUBLISH does not complete the proposed lifecycle"
    );
    for (path, stamp) in stamps {
        ensure!(
            FileStamp::read_native(&path)? == stamp,
            "historical recording changed during witness validation"
        );
    }
    println!(
        "{}",
        json!({"kind":"independent_historical_source_witness",
        "target_verified":false,"source_manifest_digest":manifest_digest,
        "case_id":case_id,"exchange_id":exchange_id,"scenario_index":scenario,
        "end_rule_fingerprint":crate::policy_evidence::digest(&serde_json::to_vec(ends)?)})
    );
    Ok(())
}
