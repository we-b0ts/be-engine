//! Native protected-witness planning and fresh runtime verification.
use super::*;
use crate::replay::policy::matcher::ReplayPolicyRuntime;
use crate::replay::{ReplayCase, ReplayCaseStatus, TargetKey};
use std::collections::BTreeMap;

struct Fixture {
    _temp: tempfile::TempDir,
    policy: PathBuf,
    case: PathBuf,
    report: PathBuf,
    identity: DynamicValueRule,
    time: DynamicValueRedisTimeRule,
    request: Value,
    events: Vec<Value>,
    candidates: Vec<request_contract::Candidate>,
    source: Vec<Vec<u8>>,
    actual: Vec<Vec<u8>>,
    command: String,
}

fn target() -> TargetKey {
    TargetKey {
        host: "cache.test".into(),
        port: 6379,
    }
}
fn captured(value: &[u8]) -> Value {
    json!({"encoding":"utf8","data":String::from_utf8(value.to_vec()).unwrap(),"truncated":false})
}
fn payload(id: &str, stamp: i64) -> Value {
    json!({"id":id,"timestamp":stamp,"content_key":format!("cache:payload:7:{id}"),"label":"stable","owner":7})
}
fn arguments(payload: &Value) -> Vec<Vec<u8>> {
    vec![b"items:7".to_vec(), payload.to_string().into_bytes()]
}
impl Fixture {
    fn new(command: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path().join(".traffic-e2e/local");
        let case = local.join("recordings/run/case");
        fs::create_dir_all(&case).unwrap();
        fs::write(case.join("expected-response.json"), "{}").unwrap();
        let key = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
        fs::create_dir_all(key.parent().unwrap()).unwrap();
        fs::write(
            key,
            crate::request_headers::generate_encryption_key().unwrap(),
        )
        .unwrap();
        let policy = temp.path().join(".traffic-e2e/verification.yaml");
        fs::write(
            &policy,
            "# keep\nversion: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        let identity = serde_json::from_value(json!({
            "id":"item-id","api":"/items","targets":[{"host":"cache.test","port":6379}],
            "when":{"request_body_json":{"/mode":{"equals":"generated"}}},
            "capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},"database":0,
                "command":command,"key":{"prefix":"items:","numeric":true},"argument_index":1,
                "json_pointer":"/id","references":[{"json_pointer":"/content_key","template":"cache:payload:{key_middle}:{value}"}],
                "derived_from":{"json_pointer":"/timestamp","prefix":"item-"}},
            "source_evidence":"Item:create generates an identity from current milliseconds and its exact payload reference"
        })).unwrap();
        let mut fixture = Self {
            report: temp.path().join("replay.json"),
            _temp: temp,
            policy,
            case,
            identity,
            time: DynamicValueRedisTimeRule {
                id: "item-time".into(),
                method: "POST".into(),
                time_values: vec![RedisJsonTimeValueSelector {
                    json_pointer: "/timestamp".into(),
                    format: "unix_milliseconds".into(),
                }],
                source_evidence:
                    "Item:create stores the current request-relative millisecond timestamp".into(),
            },
            request: json!({"method":"POST","uri":"/items","timestamp":"1970-01-01T00:16:40Z",
                "body":{"encoding":"utf8","truncated":false,"data":"{\"mode\":\"generated\"}"}}),
            events: Vec::new(),
            candidates: Vec::new(),
            source: Vec::new(),
            actual: Vec::new(),
            command: command.into(),
        };
        fixture.source = arguments(&payload("item-1000100", 1000100));
        fixture.actual = arguments(&payload("item-2000100", 2000100));
        fixture.publish();
        fixture
    }
    fn cases(&self) -> BTreeMap<String, ReplayCase> {
        BTreeMap::from([(
            "case".into(),
            ReplayCase {
                id: "case".into(),
                dir: self.case.clone(),
                dependencies_path: self.case.join("dependencies.jsonl"),
                status: ReplayCaseStatus::Pending,
            },
        )])
    }
    fn publish(&mut self) {
        fs::write(self.case.join("request.json"), self.request.to_string()).unwrap();
        let runtime =
            request_contract::RequestContracts::load(&[], &self.policy, &self.cases()).unwrap();
        runtime.set_request_times(
            "case",
            crate::replay::assertion::RequestTimes {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
        );
        runtime.observe_redis(
            "case",
            &target(),
            0,
            &self.command,
            &self.source,
            &self.actual,
        );
        self.candidates = runtime.candidates();
        self.events = vec![
            json!({"event_type":"redis_exchange","target_host":"cache.test","target_port":6379,
            "database":0,"command":self.command,"outcome":"response","replay_safe":true,
            "args":self.source.iter().map(|v|captured(v)).collect::<Vec<_>>(),"response":captured(b"+OK\r\n")}),
        ];
        self.write_report(json!([]));
    }
    fn write_report(&self, bindings: Value) {
        fs::write(
            self.case.join("dependencies.jsonl"),
            self.events
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        fs::write(
            &self.report,
            json!({"finalized":true,"complete":false,
            "replay_policy":{"fingerprint":load_replay_policy(&self.policy).unwrap().fingerprint,
                "request_contract_candidates":self.candidates,"dynamic_bindings":bindings},
            "cases":[{"case_id":"case","case_dir":self.case}]})
            .to_string(),
        )
        .unwrap();
    }
    fn feedback(&self) -> DynamicValueRuleFeedback {
        DynamicValueRuleFeedback {
            policy_path: self.policy.clone(),
            rule: self.identity.clone(),
            replay_report: self.report.clone(),
        }
    }
    fn plan(&self) -> Result<GeneratedValueRulePlan> {
        plan_dynamic_value_redis_time_rule(self.feedback(), self.time.clone())
    }
    fn actual_json(&mut self, edit: impl FnOnce(&mut Value)) {
        let mut actual: Value = serde_json::from_slice(&self.actual[1]).unwrap();
        edit(&mut actual);
        self.actual[1] = actual.to_string().into_bytes();
        self.publish();
    }
}

#[test]
fn redis_joint_set_and_rpush_plan_atomically_then_verify_fresh_runtime() {
    for command in ["SET", "RPUSH"] {
        let fixture = Fixture::new(command);
        let original = fs::read(fixture.case.join("dependencies.jsonl")).unwrap();
        // There is intentionally no dynamic_capture_candidates hint, including for SET.
        let plan = fixture.plan().unwrap();
        assert_eq!(plan.report().kind, "dynamic_value_redis_time");
        assert_eq!(plan.report().matching_cases, 1);
        assert_eq!(plan.report().added_rule_ids, ["item-id", "item-time"]);
        assert!(plan.report().requires_fresh_replay);
        plan.apply().unwrap();
        assert!(
            fs::read_to_string(&fixture.policy)
                .unwrap()
                .starts_with("# keep\n")
        );
        let loaded = load_replay_policy(&fixture.policy).unwrap();
        let time = &loaded.document.dependency_rules[0];
        assert_eq!(time.target.host.as_deref(), Some("cache.test"));
        assert_eq!(time.target.port, Some(6379));
        assert_eq!(time.when, fixture.identity.when);
        let runtime = ReplayPolicyRuntime::load(&fixture.policy, &fixture.cases()).unwrap();
        runtime.request_contracts.set_request_times(
            "case",
            crate::replay::assertion::RequestTimes {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
        );
        let normalized = runtime
            .dynamic_values
            .redis(
                Some("case"),
                &target(),
                0,
                command,
                &fixture.source,
                &fixture.actual,
            )
            .unwrap()
            .unwrap();
        let decision = runtime
            .request_contracts
            .preview_redis(
                "case",
                &target(),
                0,
                command,
                &normalized.source,
                &normalized.actual,
            )
            .unwrap();
        assert!(decision.is_ok());
        runtime.dynamic_values.commit("case", normalized.decision);
        let normalized = runtime
            .dynamic_values
            .normalize_arguments(
                Some("case"),
                &target(),
                &[b"cache:payload:7:item-1000100".to_vec()],
                &[b"cache:payload:7:item-2000100".to_vec()],
            )
            .unwrap()
            .unwrap();
        assert_eq!(normalized.0, normalized.1);
        assert_eq!(
            fs::read(fixture.case.join("dependencies.jsonl")).unwrap(),
            original
        );
    }
}

#[test]
fn redis_joint_rejects_unselected_fields_invalid_refs_clock_and_derived_identity() {
    for mutation in [
        "stable",
        "ref_prefix",
        "ref_owner",
        "ref_id",
        "derived",
        "clock",
        "missing_time",
        "missing_ref",
        "duplicate_json",
        "same_identity",
    ] {
        let mut fixture = Fixture::new("RPUSH");
        match mutation {
            "stable" => fixture.actual_json(|v| v["label"] = json!("changed")),
            "ref_prefix" => {
                fixture.actual_json(|v| v["content_key"] = json!("other:payload:7:item-2000100"))
            }
            "ref_owner" => {
                fixture.actual_json(|v| v["content_key"] = json!("cache:payload:8:item-2000100"))
            }
            "ref_id" => {
                fixture.actual_json(|v| v["content_key"] = json!("cache:payload:7:other-id"))
            }
            "derived" => fixture.actual_json(|v| v["id"] = json!("item-2000101")),
            "clock" => fixture.actual_json(|v| {
                v["timestamp"] = json!(9000100);
                v["id"] = json!("item-9000100");
                v["content_key"] = json!("cache:payload:7:item-9000100");
            }),
            "missing_time" => fixture.actual_json(|v| {
                v.as_object_mut().unwrap().remove("timestamp");
            }),
            "missing_ref" => fixture.actual_json(|v| {
                v.as_object_mut().unwrap().remove("content_key");
            }),
            "duplicate_json" => {
                fixture.actual[1]=br#"{"id":"item-2000100","id":"other","timestamp":2000100,"content_key":"cache:payload:7:item-2000100","label":"stable","owner":7}"#.to_vec();
                fixture.publish();
            }
            "same_identity" => fixture.actual_json(|v| {
                v["id"] = json!("item-1000100");
                v["content_key"] = json!("cache:payload:7:item-1000100");
            }),
            _ => unreachable!(),
        }
        let original = fs::read(&fixture.policy).unwrap();
        assert!(fixture.plan().is_err(), "{mutation}");
        assert_eq!(fs::read(&fixture.policy).unwrap(), original);
    }
}

#[test]
fn redis_joint_inherits_scope_and_requires_complete_same_case_evidence() {
    for mutation in [
        "method",
        "route",
        "guard",
        "missing_body",
        "database",
        "key",
        "endpoint",
        "truncated",
        "source_error",
        "stale",
        "unfinalized",
    ] {
        let mut fixture = Fixture::new("SET");
        match mutation {
            "method" => fixture.time.method = "PUT".into(),
            "route" => fixture.identity.api = "/other".into(),
            "guard" => {
                fixture.request["body"]["data"] = json!("{\"mode\":\"forwarded\"}");
                fixture.publish();
            }
            "missing_body" => {
                fixture.request.as_object_mut().unwrap().remove("body");
                fixture.publish();
            }
            "database" => {
                if let DynamicValueCapture::Redis { database, .. } = &mut fixture.identity.capture {
                    *database = 1;
                }
            }
            "key" => {
                if let DynamicValueCapture::Redis { key, .. } = &mut fixture.identity.capture {
                    *key = crate::RedisValueKeySelector::Exact {
                        value: "items:8".into(),
                    };
                }
            }
            "endpoint" => {
                if let DynamicValueCapture::Redis { target, .. } = &mut fixture.identity.capture {
                    target.host = "other.test".into();
                }
            }
            "truncated" => {
                fixture.events[0]["args"][1]["truncated"] = json!(true);
                fixture.write_report(json!([]));
            }
            "source_error" => {
                fixture.events[0]["outcome"] = json!("error");
                fixture.write_report(json!([]));
            }
            "stale" => fs::write(
                &fixture.policy,
                format!(
                    "{}# changed\n",
                    fs::read_to_string(&fixture.policy).unwrap()
                ),
            )
            .unwrap(),
            "unfinalized" => {
                let mut report: Value =
                    serde_json::from_slice(&fs::read(&fixture.report).unwrap()).unwrap();
                report["finalized"] = json!(false);
                fs::write(&fixture.report, report.to_string()).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(fixture.plan().is_err(), "{mutation}");
    }
}

#[test]
fn redis_joint_pending_identity_cannot_excuse_substring_changes_in_other_fields_or_arguments() {
    for other_argument in [false, true] {
        let mut fixture = Fixture::new("RPUSH");
        if let DynamicValueCapture::Redis { derived_from, .. } = &mut fixture.identity.capture {
            *derived_from = None;
        }
        let mut source = payload("a", 1000100);
        let mut actual = payload("b", 2000100);
        source["label"] = json!("cat");
        actual["label"] = json!(if other_argument { "cat" } else { "cbt" });
        fixture.source = arguments(&source);
        fixture.actual = arguments(&actual);
        if other_argument {
            fixture.source.push(b"cat".to_vec());
            fixture.actual.push(b"cbt".to_vec());
        }
        fixture.publish();
        assert!(fixture.plan().is_err());
    }
}

#[test]
fn redis_joint_checks_existing_report_bindings_bidirectionally() {
    for mode in ["same", "rebind", "collapse"] {
        let fixture = Fixture::new("SET");
        let mut loaded = load_replay_policy(&fixture.policy).unwrap();
        loaded
            .document
            .dynamic_values
            .push(fixture.identity.clone());
        let original = fs::read_to_string(&fixture.policy).unwrap();
        fs::write(
            &fixture.policy,
            replace_dependency_rules(&original, &loaded.document).unwrap(),
        )
        .unwrap();
        let source = if mode == "collapse" {
            "item-previous"
        } else {
            "item-1000100"
        };
        let target = if mode == "rebind" {
            "item-previous"
        } else {
            "item-2000100"
        };
        fixture.write_report(json!([{"case_id":"case","rule_id":"item-id",
            "source_fingerprint":fingerprint(source.as_bytes()),"target_fingerprint":fingerprint(target.as_bytes())}]));
        assert_eq!(fixture.plan().is_ok(), mode == "same", "{mode}");
    }
}

#[test]
fn redis_joint_validates_multiple_new_pairs_as_one_case_binding_set() {
    for mode in ["distinct", "rebind", "collapse"] {
        let mut fixture = Fixture::new("RPUSH");
        if let DynamicValueCapture::Redis { derived_from, .. } = &mut fixture.identity.capture {
            *derived_from = None;
        }
        let source_id = if mode == "rebind" {
            "item-1000100"
        } else {
            "item-next"
        };
        let target_id = if mode == "collapse" {
            "item-2000100"
        } else {
            "item-target-next"
        };
        let source = arguments(&payload(source_id, 1000200));
        let actual = arguments(&payload(target_id, 2000200));
        let runtime =
            request_contract::RequestContracts::load(&[], &fixture.policy, &fixture.cases())
                .unwrap();
        runtime.set_request_times(
            "case",
            crate::replay::assertion::RequestTimes {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
        );
        runtime.observe_redis("case", &target(), 0, "RPUSH", &source, &actual);
        fixture.candidates.extend(runtime.candidates());
        fixture.events.push(json!({"event_type":"redis_exchange","target_host":"cache.test","target_port":6379,
            "database":0,"command":"RPUSH","outcome":"response","replay_safe":true,
            "args":source.iter().map(|v|captured(v)).collect::<Vec<_>>(),"response":captured(b":2\r\n")}));
        fixture.write_report(json!([]));
        assert_eq!(fixture.plan().is_ok(), mode == "distinct", "{mode}");
    }
}

#[test]
fn redis_joint_freezes_every_witness_and_policy_before_atomic_apply() {
    for mutation in ["policy", "request", "dependencies", "report"] {
        let fixture = Fixture::new("SET");
        let plan = fixture.plan().unwrap();
        let path = match mutation {
            "policy" => fixture.policy.clone(),
            "request" => fixture.case.join("request.json"),
            "dependencies" => fixture.case.join("dependencies.jsonl"),
            "report" => fixture.report.clone(),
            _ => unreachable!(),
        };
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(b' ');
        fs::write(path, bytes).unwrap();
        let policy = fs::read(&fixture.policy).unwrap();
        assert!(plan.apply().is_err(), "{mutation}");
        assert_eq!(fs::read(&fixture.policy).unwrap(), policy);
    }
}

#[test]
fn redis_joint_schema_requires_nonoverlapping_explicit_ownership_and_supported_commands() {
    for mutation in [
        "legacy_refs",
        "bad_format",
        "identity_time",
        "reference_time",
        "missing_derived_time",
        "duplicate_time",
        "hset",
        "duplicate_refs",
        "template_wildcard",
        "unbounded_middle",
    ] {
        let mut fixture = Fixture::new("SET");
        match mutation {
            "legacy_refs" => {
                if let DynamicValueCapture::Redis { references, .. } = &mut fixture.identity.capture
                {
                    *references = None;
                }
            }
            "bad_format" => fixture.time.time_values[0].format = "any_time".into(),
            "identity_time" => fixture.time.time_values[0].json_pointer = "/id".into(),
            "reference_time" => fixture.time.time_values[0].json_pointer = "/content_key".into(),
            "missing_derived_time" => {
                fixture.time.time_values[0].json_pointer = "/other_time".into()
            }
            "duplicate_time" => fixture
                .time
                .time_values
                .push(fixture.time.time_values[0].clone()),
            "hset" => {
                if let DynamicValueCapture::Redis {
                    command,
                    argument_index,
                    ..
                } = &mut fixture.identity.capture
                {
                    *command = "HSET".into();
                    *argument_index = 2;
                }
            }
            "duplicate_refs" => {
                if let DynamicValueCapture::Redis {
                    references: Some(refs),
                    ..
                } = &mut fixture.identity.capture
                {
                    refs.push(refs[0].clone());
                }
            }
            "template_wildcard" => {
                if let DynamicValueCapture::Redis {
                    references: Some(refs),
                    ..
                } = &mut fixture.identity.capture
                {
                    refs[0].template = "{unknown}:{value}".into();
                }
            }
            "unbounded_middle" => {
                if let DynamicValueCapture::Redis { key, .. } = &mut fixture.identity.capture {
                    *key = crate::RedisValueKeySelector::Affix {
                        prefix: "items:".into(),
                        suffix: String::new(),
                    };
                }
            }
            _ => unreachable!(),
        }
        assert!(fixture.plan().is_err(), "{mutation}");
    }
    let fixture = Fixture::new("SET");
    assert!(plan_dynamic_value_rule(fixture.feedback()).is_err());
}

#[test]
fn redis_joint_opaque_identity_and_prefix_free_integer_derivation_are_general_contracts() {
    for derived in [false, true] {
        let mut fixture = Fixture::new("SET");
        if let DynamicValueCapture::Redis { derived_from, .. } = &mut fixture.identity.capture {
            *derived_from = derived.then(|| crate::RedisDerivedIdentity {
                json_pointer: "/timestamp".into(),
                prefix: String::new(),
            });
        }
        fixture.source = arguments(&payload(
            if derived {
                "1000100"
            } else {
                "random-source-name"
            },
            1000100,
        ));
        fixture.actual = arguments(&payload(
            if derived {
                "2000100"
            } else {
                "random-target-name"
            },
            2000100,
        ));
        fixture.publish();
        assert!(fixture.plan().is_ok());
    }
}

#[test]
fn redis_json_reference_ownership_cannot_mask_another_capture_validation() {
    let fixture = Fixture::new("SET");
    let mut left = fixture.identity.clone();
    if let DynamicValueCapture::Redis {
        json_pointer,
        references,
        derived_from,
        ..
    } = &mut left.capture
    {
        *json_pointer = Some("/a".into());
        *derived_from = None;
        *references = Some(vec![crate::RedisCaptureReference {
            json_pointer: "/b".into(),
            template: "{value}".into(),
        }]);
    }
    let mut right = left.clone();
    right.id = "uuid-field".into();
    right.format = Some(crate::DynamicValueFormat::UuidV4);
    if let DynamicValueCapture::Redis {
        json_pointer,
        references,
        ..
    } = &mut right.capture
    {
        *json_pointer = Some("/b".into());
        *references = Some(vec![]);
    }
    // A first rule must not rewrite /b before the second rule validates its
    // original Target UUID. Either order has identical ownership rejection.
    assert!(
        crate::replay::policy::dynamic_values::validate(&[left.clone(), right.clone()]).is_err()
    );
    assert!(
        crate::replay::policy::dynamic_values::validate(&[right.clone(), left.clone()]).is_err()
    );
    right.when = Some(
        serde_json::from_value(json!({"request_body_json":{"/mode":{"equals":"forwarded"}}}))
            .unwrap(),
    );
    assert!(crate::replay::policy::dynamic_values::validate(&[left, right]).is_ok());
}
