//! Bounded target-request witnesses; public discovery exposes selectors only.
use super::super::config::fingerprint;
use super::*;
use serde::{Deserialize, Serialize};
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Candidate {
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
    #[serde(flatten)]
    pub payload: crate::policy_evidence::StoredPayload,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authentication: String,
}
impl Candidate {
    fn actual(&self, context: &Path) -> Result<Vec<u8>> {
        let bytes = self.payload.read(context, &self.label())?;
        if !matches!(
            self.payload,
            crate::policy_evidence::StoredPayload::Encrypted { .. }
        ) || !self.authentication.is_empty()
        {
            crate::policy_evidence::authentication::verify(
                context,
                &self.label(),
                &bytes,
                &self.authentication,
            )?;
        }
        Ok(bytes)
    }

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
    pub contract: crate::protocols::replay::http::multipart::MultipartContract,
    pub headers: BTreeMap<String, Vec<String>>,
}
impl RequestContracts {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_redis(
        &self,
        case: &str,
        target: &TargetKey,
        database: i64,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
        clocks: crate::primary_protocol::assertion::RequestTimes,
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
            crate::json_value::parse(&source[index]).is_some()
                && crate::json_value::parse(&actual[index]).is_some()
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
    pub(crate) fn observe_http(
        &self,
        case: &str,
        target: &TargetKey,
        method: &str,
        path: &str,
        source: &[u8],
        source_headers: &BTreeMap<String, Vec<String>>,
        actual: &[u8],
        headers: &BTreeMap<String, Vec<String>>,
        clocks: crate::primary_protocol::assertion::RequestTimes,
    ) {
        if source == actual {
            return;
        }
        if crate::protocols::replay::http::multipart::compare(
            source,
            source_headers,
            actual,
            headers,
        )
        .is_err()
        {
            return;
        }
        let actual = serde_json::to_vec(&HttpWitness {
            contract: crate::protocols::replay::http::multipart::contract(actual, headers)
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
        if actual.len() > crate::value_limits::MAX_VALUE_BYTES {
            return;
        }
        let Ok(anchor) = self.anchor(case) else {
            return;
        };
        let Some(actual_anchor) = actual_started_at else {
            return;
        };
        let Ok(headers) = crate::request_headers::evidence::HeaderPolicy::load(&anchor.dir)
            .and_then(|policy| policy.ranges(actual))
        else {
            return;
        };
        let Ok(payload) =
            crate::policy_evidence::StoredPayload::capture(actual, 0, &headers, &anchor.dir)
        else {
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
            payload,
            authentication: String::new(),
        };
        let Ok(authentication) =
            crate::policy_evidence::authentication::sign(&anchor.dir, &candidate.label(), actual)
        else {
            return;
        };
        candidate.authentication = authentication;
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
                for field in [
                    "encrypted_target",
                    "encrypted",
                    "encoding",
                    "data",
                    "parts",
                    "authentication",
                ] {
                    candidate.as_object_mut().unwrap().remove(field);
                }
                candidate
            })
            .collect(),
    )
}

pub(crate) fn verify(
    runtime: &RequestContracts,
    rule: &ReplayDependencyRule,
    report: &Value,
    document: &super::super::config::ReplayPolicyDocument,
    witnesses: &mut Vec<(PathBuf, String)>,
) -> Result<usize> {
    runtime.restore_key_binding_proofs(report)?;
    verify_capture(runtime, rule, report, document, witnesses, None)
}

pub(crate) fn verify_capture(
    runtime: &RequestContracts,
    rule: &ReplayDependencyRule,
    report: &Value,
    document: &super::super::config::ReplayPolicyDocument,
    witnesses: &mut Vec<(PathBuf, String)>,
    capture_id: Option<&str>,
) -> Result<usize> {
    let dynamic_rules = &document.dynamic_values;
    let mut validated = BTreeSet::new();
    let mut matched_cases = BTreeSet::new();
    let mut dynamic_cases = BTreeMap::new();
    for item in report["replay_policy"]["request_contract_candidates"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let candidate: Candidate = serde_json::from_value(item.clone())?;
        let protocol = if candidate.capability == "http_multipart" {
            DependencyProtocol::Http
        } else {
            DependencyProtocol::Redis
        };
        if rule.protocol != protocol
            || rule
                .target
                .host
                .as_ref()
                .is_some_and(|host| !host.eq_ignore_ascii_case(&candidate.host))
            || rule.target.port.is_some_and(|port| port != candidate.port)
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
        if rule
            .when
            .as_ref()
            .is_some_and(|condition| !condition.matches_request(&request))
            || rule.case_selector.as_ref().is_some_and(|scope| {
                request["method"] != scope.method
                    || !super::super::pattern::path_pattern_matches(
                        &scope.path,
                        &super::super::pattern::uri_path(
                            request["uri"].as_str().unwrap_or_default(),
                        ),
                    )
            })
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
        let source_body = super::unified::source_body(&request);
        let source_input_error =
            super::identity_inputs::capture_error(&request, source_body.as_ref());
        runtime
            .state
            .lock()
            .expect("request contracts")
            .cases
            .insert(
                candidate.case_id.clone(),
                CaseAnchor {
                    source_input_error,
                    source_uri: request["uri"].as_str().unwrap_or_default().to_owned(),
                    source_body,
                    method: request["method"]
                        .as_str()
                        .context("Source method missing")?
                        .into(),
                    path: super::super::pattern::uri_path(request["uri"].as_str().unwrap()),
                    recorded,
                    actual: Some(candidate.actual_anchor),
                    dir: dir.clone(),
                    dependencies_path: dir.join("dependencies.jsonl"),
                    conditions: BTreeSet::from([rule.id.clone()]),
                },
            );
        let actual = candidate.actual(&dir)?;
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
            if event
                .get("outcome")
                .is_some_and(|outcome| outcome != "response")
                || !crate::dependency::observation::is_case_event(&event)
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
                if selector
                    .database
                    .is_some_and(|database| database != candidate.database)
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
                    source_args,
                    actual_args,
                )?;
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
                    dynamic.commit(&candidate.case_id, normalized.decision)?;
                }
                if !capture_differs {
                    continue;
                }
                validated.insert(candidate.command.clone());
                matched_cases.insert(candidate.case_id.clone());
            } else {
                let uri_matches = event["uri"] == candidate.path;
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
                    crate::protocols::replay::http::request_headers::exact_contract_match(
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
                    crate::protocols::replay::http::multipart::contract(&source, &headers)?
                        == actual.contract,
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
            || event["database"] != candidate.database
            || event["target_host"] != candidate.host
            || event["target_port"] != candidate.port
            || event["replay_safe"] != true
            || !crate::dependency::observation::is_case_event(&event)
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
                    let json = crate::json_value::parse(bytes)
                        .context("source JSON request incomplete")?;
                    for (pattern, field) in &fields.json {
                        let pointers = crate::policy::runtime::response::select_json_pointers(
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
