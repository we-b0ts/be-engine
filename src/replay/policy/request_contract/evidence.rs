//! Bounded encrypted target-request witnesses; public discovery exposes selectors only.
use super::super::config::fingerprint;
use super::*;
use serde::{Deserialize, Serialize};
mod http_json;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::replay) struct Candidate {
    pub case_id: String,
    pub capability: String,
    pub host: String,
    pub port: u16,
    pub command: String,
    pub database: i64,
    pub path: String,
    pub source_fingerprint: String,
    pub target_fingerprint: String,
    pub actual_anchor: DateTime<Utc>,
    pub encrypted_target: String,
}
impl Candidate {
    fn label(&self) -> String {
        let metadata = serde_json::to_string(&(
            &self.case_id,
            &self.capability,
            &self.host,
            self.port,
            &self.command,
            self.database,
            &self.path,
            &self.source_fingerprint,
            &self.target_fingerprint,
            self.actual_anchor,
        ))
        .expect("witness metadata serialization");
        format!("dependency-request:{metadata}")
    }
}
#[derive(Serialize, Deserialize)]
pub(super) struct HttpWitness {
    pub contract: crate::replay::http::multipart::MultipartContract,
    pub headers: BTreeMap<String, Vec<String>>,
}
impl RequestContracts {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay) fn observe_redis(
        &self,
        case: &str,
        target: &TargetKey,
        database: i64,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
        clocks: crate::replay::assertion::RequestTimes,
    ) {
        if source.len() != actual.len() || source == actual {
            return;
        }
        let capability = if source.first() != actual.first()
            && matches!(command, "SET" | "INCRBY" | "EXPIRE")
            && source
                .first()
                .is_some_and(|v| v.len() <= 1024 && std::str::from_utf8(v).is_ok())
            && actual
                .first()
                .is_some_and(|v| v.len() <= 1024 && std::str::from_utf8(v).is_ok())
        {
            "redis_key_request"
        } else if source.first() != actual.first() {
            return;
        } else if (if command == "RPUSH" && source.len() >= 2 {
            Some(1)
        } else {
            super::unified::value_index(command, source.len())
        })
        .is_some_and(|index| {
            crate::replay::json_order::parse(&source[index]).is_some()
                && crate::replay::json_order::parse(&actual[index]).is_some()
        }) {
            "redis_json_request"
        } else if matches!(command, "ZADD" | "ZREMRANGEBYSCORE") && source.len() == 3 {
            "redis_request_time"
        } else if matches!(command, "EVAL" | "EVALSHA") && source.len() >= 4 && source.len() <= 129
        {
            "redis_script_request_time"
        } else {
            return;
        };
        let source = serde_json::to_vec(source).expect("argument serialization");
        let actual = serde_json::to_vec(actual).expect("argument serialization");
        self.observe(
            case,
            target,
            command,
            database,
            "",
            capability,
            &source,
            &actual,
            clocks.target,
        );
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay) fn observe_http(
        &self,
        case: &str,
        target: &TargetKey,
        method: &str,
        path: &str,
        source: &[u8],
        source_headers: &BTreeMap<String, Vec<String>>,
        actual: &[u8],
        headers: &BTreeMap<String, Vec<String>>,
        clocks: crate::replay::assertion::RequestTimes,
        actual_uri: &str,
    ) {
        if source == actual {
            return;
        }
        self.observe_http_json(
            case,
            target,
            method,
            path,
            source,
            source_headers,
            actual,
            headers,
            clocks,
            actual_uri,
        );
        if crate::replay::http::multipart::compare(source, source_headers, actual, headers).is_err()
        {
            return;
        }
        let actual = serde_json::to_vec(&HttpWitness {
            contract: crate::replay::http::multipart::contract(actual, headers)
                .expect("validated multipart request"),
            headers: headers.clone(),
        })
        .expect("HTTP witness serialization");
        self.observe(
            case,
            target,
            method,
            0,
            path,
            "http_multipart",
            source,
            &actual,
            clocks.target,
        );
    }
    #[allow(clippy::too_many_arguments)]
    fn observe(
        &self,
        case: &str,
        target: &TargetKey,
        command: &str,
        database: i64,
        path: &str,
        capability: &str,
        source: &[u8],
        actual: &[u8],
        actual_started_at: Option<DateTime<Utc>>,
    ) {
        if actual.len() > 1024 * 1024 {
            return;
        }
        let Ok(anchor) = self.anchor(case) else {
            return;
        };
        let Some(actual_anchor) = actual_started_at else {
            return;
        };
        let mut candidate = Candidate {
            case_id: case.into(),
            capability: capability.into(),
            host: target.host.clone(),
            port: target.port,
            command: command.into(),
            database,
            path: path.into(),
            source_fingerprint: fingerprint(source),
            target_fingerprint: fingerprint(actual),
            actual_anchor,
            encrypted_target: String::new(),
        };
        let Ok(encrypted_target) =
            crate::request_headers::encrypt_evidence(&anchor.dir, &candidate.label(), actual)
        else {
            return;
        };
        candidate.encrypted_target = encrypted_target;
        let mut state = self.state.lock().expect("request contracts");
        if state.candidates.len() < 64
            && !state.candidates.iter().any(|c| {
                c.case_id == case
                    && c.source_fingerprint == candidate.source_fingerprint
                    && c.target_fingerprint == candidate.target_fingerprint
            })
        {
            state.candidates.push(candidate);
        }
    }
}

pub(crate) fn discover(report: &Value) -> Value {
    Value::Array(
        report["replay_policy"]["request_contract_candidates"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|candidate| serde_json::from_value::<Candidate>(candidate.clone()).ok())
            .map(|candidate| {
                let mut candidate = serde_json::to_value(candidate).expect("candidate projection");
                candidate
                    .as_object_mut()
                    .unwrap()
                    .remove("encrypted_target");
                candidate
            })
            .collect(),
    )
}

pub(in crate::replay::policy) fn verify(
    runtime: &RequestContracts,
    rule: &ReplayDependencyRule,
    report: &Value,
    document: &super::super::config::ReplayPolicyDocument,
    witnesses: &mut Vec<(PathBuf, String)>,
) -> Result<usize> {
    runtime.restore_key_binding_proofs(report)?;
    verify_capture(runtime, rule, report, document, witnesses, None)
}

pub(in crate::replay::policy) fn verify_capture(
    runtime: &RequestContracts,
    rule: &ReplayDependencyRule,
    report: &Value,
    document: &super::super::config::ReplayPolicyDocument,
    witnesses: &mut Vec<(PathBuf, String)>,
    capture_id: Option<&str>,
) -> Result<usize> {
    let dynamic_rules = &document.dynamic_values;
    let mut publish = crate::replay::redis::publish::PublishRules::default();
    publish.configure(super::super::redis_value::publish_rules(
        &document.dependency_rules,
    ));
    let mut validated = BTreeSet::new();
    let mut matched_cases = BTreeSet::new();
    let mut dynamic_cases = BTreeMap::new();
    for item in report["replay_policy"]["request_contract_candidates"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let candidate: Candidate = serde_json::from_value(item.clone())?;
        let protocol = if matches!(
            candidate.capability.as_str(),
            "http_multipart" | "http_json_request_time"
        ) {
            DependencyProtocol::Http
        } else {
            DependencyProtocol::Redis
        };
        if rule.protocol != protocol
            || rule
                .target
                .host
                .as_ref()
                .is_none_or(|host| !host.eq_ignore_ascii_case(&candidate.host))
            || rule.target.port != Some(candidate.port)
        {
            continue;
        }
        let Some(case) = report["cases"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|case| case["case_id"] == candidate.case_id)
        else {
            continue;
        };
        let dir = PathBuf::from(
            case["case_dir"]
                .as_str()
                .context("request witness has no case directory")?,
        );
        let read = |path: PathBuf, witnesses: &mut Vec<(PathBuf, String)>| -> Result<Vec<u8>> {
            let bytes =
                super::super::feedback::read_published_report(&path, "dependency request witness")?;
            witnesses.push((path, fingerprint(&bytes)));
            Ok(bytes)
        };
        let request: Value = serde_json::from_slice(&read(dir.join("request.json"), witnesses)?)?;
        let Some(scope) = &rule.case_selector else {
            continue;
        };
        if rule
            .when
            .as_ref()
            .is_some_and(|condition| !condition.matches_request(&request))
            || request["method"] != scope.method
            || !super::super::pattern::path_pattern_matches(
                &scope.path,
                &super::super::pattern::uri_path(request["uri"].as_str().unwrap_or_default()),
            )
        {
            continue;
        }
        let recorded = request["timestamp"].as_str().and_then(|v| v.parse().ok());
        let dynamic = dynamic_cases
            .entry(candidate.case_id.clone())
            .or_insert_with(|| {
                let mut dynamic = super::super::dynamic_values::DynamicValues::new(
                    dynamic_rules.to_vec(),
                    BTreeMap::from([(
                        candidate.case_id.clone(),
                        super::super::pattern::uri_path(
                            request["uri"].as_str().unwrap_or_default(),
                        ),
                    )]),
                );
                dynamic.set_request(&candidate.case_id, &request);
                dynamic
            })
            .clone();
        runtime
            .state
            .lock()
            .expect("request contracts")
            .cases
            .insert(
                candidate.case_id.clone(),
                CaseAnchor {
                    source_body: super::unified::source_body(&request),
                    method: scope.method.clone(),
                    path: super::super::pattern::uri_path(request["uri"].as_str().unwrap()),
                    recorded,
                    actual: Some(candidate.actual_anchor),
                    dir: dir.clone(),
                    conditions: BTreeSet::from([rule.id.clone()]),
                },
            );
        let actual = crate::request_headers::decrypt_evidence(
            &dir,
            &candidate.label(),
            &candidate.encrypted_target,
        )?;
        ensure!(
            fingerprint(&actual) == candidate.target_fingerprint,
            "request witness target fingerprint differs"
        );
        let source_bytes = read(dir.join("dependencies.jsonl"), witnesses)?;
        let mut source_commands_validated = false;
        for line in source_bytes
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
        {
            let event: Value = serde_json::from_slice(line)?;
            if event["outcome"].as_str().is_some_and(|s| s != "response")
                || event
                    .get("global_dependency_reason")
                    .is_some_and(|v| !v.is_null())
            {
                continue;
            }
            if protocol == DependencyProtocol::Redis {
                if event["event_type"] != "redis_exchange"
                    || event["target_host"]
                        .as_str()
                        .is_none_or(|host| !host.eq_ignore_ascii_case(&candidate.host))
                    || event["target_port"] != candidate.port
                    || event["database"] != candidate.database
                    || event["command"] != candidate.command
                    || event["replay_safe"] != true
                {
                    continue;
                }
                let source = event["args"]
                    .as_array()
                    .context("recorded Redis arguments unavailable")?
                    .iter()
                    .map(decode)
                    .collect::<Result<Vec<_>>>()?;
                if fingerprint(&serde_json::to_vec(&source)?) != candidate.source_fingerprint {
                    continue;
                }
                let Some(super::super::redis_value::RedisSelector::Requests(selector)) =
                    rule.redis.as_ref()
                else {
                    continue;
                };
                if selector.database != candidate.database
                    || selector
                        .commands
                        .iter()
                        .filter(|c| c.command == candidate.command)
                        .all(|c| {
                            !c.matches_identity(&source)
                                || c.key(&source).is_none_or(|key| !selector.key.matches(key))
                        })
                {
                    continue;
                }
                if !source_commands_validated {
                    validate_source_commands(selector, &candidate, &source, &source_bytes)?;
                    source_commands_validated = true;
                }
                decode(&event["response"])?;
                let actual: Vec<Vec<u8>> = serde_json::from_slice(&actual)?;
                // Planners validate individual command witnesses; runtime retains sequence correlation.
                let mut single = selector.clone();
                single
                    .commands
                    .retain(|command| command.command == candidate.command);
                if single.commands.is_empty() {
                    continue;
                }
                let normalized = dynamic
                    .redis_with_identity(
                        Some(&candidate.case_id),
                        &TargetKey {
                            host: candidate.host.clone(),
                            port: candidate.port,
                        },
                        super::super::dynamic_values::RedisIdentity {
                            database: candidate.database,
                            username: event["username"].as_str(),
                        },
                        &candidate.command,
                        &source,
                        &actual,
                    )
                    .transpose()?;
                let source_args = normalized
                    .as_ref()
                    .map_or(source.as_slice(), |n| n.source.as_slice());
                let actual_args = normalized
                    .as_ref()
                    .map_or(actual.as_slice(), |n| n.actual.as_slice());
                let publish_comparison = if candidate.command == "PUBLISH" {
                    publish
                        .preview_json(
                            crate::replay::redis::publish::json::JsonContext {
                                case_id: Some(&candidate.case_id),
                                host: &candidate.host,
                                port: candidate.port,
                                database: candidate.database,
                                username: event["username"].as_str(),
                            },
                            source_args,
                            actual_args,
                        )
                        .transpose()?
                } else {
                    None
                };
                runtime.compare_redis(
                    &super::RedisRequestContext {
                        case: &candidate.case_id,
                        target: &TargetKey {
                            host: candidate.host.clone(),
                            port: candidate.port,
                        },
                        database: candidate.database,
                        username: event["username"].as_str(),
                        command: &candidate.command,
                        recorded_at: crate::replay::recording_evidence::dependency_started_at(
                            &event,
                        ),
                        actual_at: Some(candidate.actual_anchor),
                        connection_id: None,
                        sequence: None,
                        observation_id: None,
                    },
                    rule,
                    &single,
                    publish_comparison
                        .as_ref()
                        .map_or(source_args, |c| &c.source),
                    publish_comparison
                        .as_ref()
                        .map_or(actual_args, |c| &c.actual),
                )?;
                if let Some(comparison) = publish_comparison {
                    publish.commit_json(comparison);
                }
                let capture_differs = capture_id.is_none_or(|id| {
                    normalized
                        .as_ref()
                        .is_some_and(|normalized| normalized.decision.differs(id))
                });
                if let Some(normalized) = normalized {
                    dynamic.validate_report_decision(
                        &candidate.case_id,
                        &normalized.decision,
                        report,
                    )?;
                    dynamic.commit(&candidate.case_id, normalized.decision);
                }
                if !capture_differs {
                    continue;
                }
                validated.insert(candidate.command.clone());
                matched_cases.insert(candidate.case_id.clone());
            } else {
                let uri_matches = if candidate.capability == "http_json_request_time" {
                    super::super::pattern::uri_path(event["uri"].as_str().unwrap_or_default())
                        == candidate.path
                } else {
                    event["uri"] == candidate.path
                };
                if event["event_type"] != "http_exchange"
                    || event["method"] != candidate.command
                    || !uri_matches
                    || !event["error"].is_null()
                    || !event["response_status"].is_number()
                {
                    continue;
                }
                let authority: hyper::http::uri::Authority = event["authority"]
                    .as_str()
                    .context("HTTP witness authority missing")?
                    .parse()?;
                let port = authority.port_u16().unwrap_or(
                    if event["scheme"]
                        .as_str()
                        .is_some_and(|s| s.contains("https"))
                    {
                        443
                    } else {
                        80
                    },
                );
                if !authority.host().eq_ignore_ascii_case(&candidate.host) || port != candidate.port
                {
                    continue;
                }
                let source = decode(&event["request_body"])?;
                if fingerprint(&source) != candidate.source_fingerprint {
                    continue;
                }
                decode(&event["response_body"])?;
                if candidate.capability == "http_json_request_time" {
                    if http_json::verify(rule, &candidate, &event, &source, &actual, &dir)? {
                        validated.insert(candidate.command.clone());
                        matched_cases.insert(candidate.case_id.clone());
                    }
                    continue;
                }
                let actual: HttpWitness = serde_json::from_slice(&actual)?;
                let mut headers: BTreeMap<String, Vec<String>> =
                    serde_json::from_value(event["request_headers"].clone())?;
                crate::request_headers::decrypt_dependency_headers(
                    &mut headers,
                    &dir.join("dependencies.jsonl"),
                )?;
                let mut source_identity = headers.clone();
                let mut actual_identity = actual.headers.clone();
                source_identity.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
                actual_identity.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
                ensure!(
                    crate::replay::http::request_headers::exact_contract_match(
                        &source_identity,
                        &actual_identity
                    ),
                    "multipart witness identity headers differ"
                );
                let selector = rule.http.as_ref().context("missing HTTP selector")?;
                if selector.multipart.is_none()
                    || selector.method != candidate.command
                    || !super::super::pattern::path_pattern_matches(
                        &selector.path,
                        &super::super::pattern::uri_path(&candidate.path),
                    )
                {
                    continue;
                }
                ensure!(
                    crate::replay::http::multipart::contract(&source, &headers)? == actual.contract,
                    "multipart witness parts differ"
                );
                validated.insert(candidate.command.clone());
                matched_cases.insert(candidate.case_id.clone());
            }
        }
    }
    // A failed first write prevents later calls. Source evidence may select subsequent
    // time commands, but every configured command must be present in immutable source.
    ensure!(
        !validated.is_empty(),
        "request rule requires a current same-case matching failure witness"
    );
    Ok(matched_cases.len())
}
pub(super) fn decode(value: &Value) -> Result<Vec<u8>> {
    use base64::Engine;
    ensure!(
        value["truncated"] == false,
        "request witness capture is incomplete"
    );
    let data = value["data"]
        .as_str()
        .context("request witness bytes unavailable")?;
    match value["encoding"].as_str() {
        Some("utf8") => Ok(data.as_bytes().to_vec()),
        Some("base64") => Ok(base64::engine::general_purpose::STANDARD.decode(data)?),
        _ => anyhow::bail!("unsupported request witness encoding"),
    }
}

fn validate_source_commands(
    selector: &config::RedisRequestSelector,
    candidate: &Candidate,
    source: &[Vec<u8>],
    bytes: &[u8],
) -> Result<()> {
    let selected_command = selector
        .commands
        .iter()
        .find(|c| c.command == candidate.command)
        .context("source command is not selected")?;
    let source_key = selected_command
        .key(source)
        .context("source request witness key is missing")?;
    let mut found = BTreeSet::new();
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let event: Value = serde_json::from_slice(line)?;
        if event["event_type"] != "redis_exchange"
            || event["database"] != selector.database
            || event["target_host"] != candidate.host
            || event["target_port"] != candidate.port
            || event["replay_safe"] != true
            || event
                .get("global_dependency_reason")
                .is_some_and(|v| !v.is_null())
        {
            continue;
        }
        let Some(command) = selector
            .commands
            .iter()
            .find(|c| event["command"] == c.command)
        else {
            continue;
        };
        let args = event["args"]
            .as_array()
            .context("source Redis arguments missing")?
            .iter()
            .map(decode)
            .collect::<Result<Vec<_>>>()?;
        if command.key(&args) != Some(source_key)
            || command
                .key(&args)
                .is_none_or(|key| !selector.key.matches(key))
        {
            continue;
        }
        if !command.matches_identity(&args) {
            continue;
        }
        command.validate_arguments(&args)?;
        decode(&event["response"])?;
        for (index, field) in &command.argument_values {
            let bytes = args
                .get(*index)
                .context("source selected argument missing")?;
            match field {
                config::ArgumentRule::Time(field) => {
                    super::time::timestamp(&serde_json::from_slice(bytes)?, field)?;
                }
                config::ArgumentRule::Json(fields) => {
                    let json = crate::replay::json_order::parse(bytes)
                        .context("source JSON request incomplete")?;
                    for (pattern, field) in &fields.json {
                        let pointers = crate::replay::policy::response::select_json_pointers(
                            pattern, &json, &json,
                        );
                        ensure!(
                            !pointers.is_empty() && pointers.len() <= 16384,
                            "source selected JSON fields missing or exceed bounds"
                        );
                        for pointer in &pointers {
                            let value = json
                                .pointer(pointer)
                                .context("source selected JSON field missing")?;
                            match field {
                                config::JsonField::Url(field) => field.validate_source(value)?,
                                config::JsonField::Random(field) => {
                                    field.random.compare(value, value)?
                                }
                                config::JsonField::Identity(_) => {
                                    ensure!(
                                        value.is_string(),
                                        "source identity reference is not a string"
                                    );
                                }
                                config::JsonField::Time(field) => {
                                    super::time::timestamp(value, field)?;
                                }
                                config::JsonField::Jwt(_) => {
                                    ensure!(value.is_string(), "source JWT field must be a string");
                                }
                            }
                        }
                    }
                }
            }
        }
        found.insert(command.command.clone());
    }
    ensure!(
        selector.commands.iter().all(|c| found.contains(&c.command)),
        "every configured Redis request command requires immutable same-case source evidence"
    );
    Ok(())
}
