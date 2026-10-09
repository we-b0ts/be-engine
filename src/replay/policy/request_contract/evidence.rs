//! Bounded encrypted target-request witnesses; public discovery exposes selectors only.
use super::super::config::fingerprint;
use super::*;
use serde::{Deserialize, Serialize};

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
    pub(in crate::replay) fn observe_redis(
        &self,
        case: &str,
        target: &TargetKey,
        database: i64,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) {
        if source.len() != actual.len() || source.first() != actual.first() || source == actual {
            return;
        }
        let capability = if command == "SET"
            && source.len() >= 2
            && crate::replay::json_order::parse(&source[1]).is_some()
            && crate::replay::json_order::parse(&actual[1]).is_some()
        {
            "redis_json_request"
        } else if matches!(command, "ZADD" | "ZREMRANGEBYSCORE") && source.len() == 3 {
            "redis_request_time"
        } else {
            return;
        };
        let source = serde_json::to_vec(source).expect("argument serialization");
        let actual = serde_json::to_vec(actual).expect("argument serialization");
        self.observe(
            case, target, command, database, "", capability, &source, &actual,
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
    ) {
        if source == actual
            || crate::replay::http::multipart::compare(source, source_headers, actual, headers)
                .is_err()
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
    ) {
        if actual.len() > 1024 * 1024 {
            return;
        }
        let Ok(anchor) = self.anchor(case) else {
            return;
        };
        let Some(actual_anchor) = anchor.actual else {
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
    witnesses: &mut Vec<(PathBuf, String)>,
) -> Result<usize> {
    let mut validated = BTreeSet::new();
    let mut matched_cases = BTreeSet::new();
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
        if request["method"] != scope.method
            || !super::super::pattern::path_pattern_matches(
                &scope.path,
                &super::super::pattern::uri_path(request["uri"].as_str().unwrap_or_default()),
            )
        {
            continue;
        }
        let recorded = request["timestamp"].as_str().and_then(|v| v.parse().ok());
        runtime
            .state
            .lock()
            .expect("request contracts")
            .cases
            .insert(
                candidate.case_id.clone(),
                CaseAnchor {
                    method: scope.method.clone(),
                    path: super::super::pattern::uri_path(request["uri"].as_str().unwrap()),
                    recorded,
                    actual: Some(candidate.actual_anchor),
                    dir: dir.clone(),
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
        let source = read(dir.join("dependencies.jsonl"), witnesses)?;
        if let Some(super::super::redis_value::RedisSelector::Requests(selector)) = &rule.redis {
            validate_source_commands(selector, &candidate, &source)?;
        }
        for line in source
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
                decode(&event["response"])?;
                let actual: Vec<Vec<u8>> = serde_json::from_slice(&actual)?;
                let Some(super::super::redis_value::RedisSelector::Requests(selector)) =
                    rule.redis.as_ref()
                else {
                    continue;
                };
                if selector.database != candidate.database
                    || source.first().is_none_or(|key| !selector.key.matches(key))
                {
                    continue;
                }
                // Planners validate individual command witnesses; runtime retains sequence correlation.
                let mut single = selector.clone();
                single
                    .commands
                    .retain(|command| command.command == candidate.command);
                if single.commands.is_empty() {
                    continue;
                }
                runtime.compare_redis(
                    &candidate.case_id,
                    rule,
                    &single,
                    &candidate.command,
                    &source,
                    &actual,
                )?;
                validated.insert(candidate.command.clone());
                matched_cases.insert(candidate.case_id.clone());
            } else {
                if event["event_type"] != "http_exchange"
                    || event["method"] != candidate.command
                    || event["uri"] != candidate.path
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
                    crate::replay::http::request_headers::exact_contract_match(
                        &source_identity,
                        &actual_identity
                    ),
                    "multipart witness identity headers differ"
                );
                let selector = rule.http.as_ref().context("missing HTTP selector")?;
                if selector.method != candidate.command
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
    bytes: &[u8],
) -> Result<()> {
    let events = bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let source_key = events
        .iter()
        .filter(|e| e["event_type"] == "redis_exchange" && e["command"] == candidate.command)
        .find_map(|e| {
            let args = e["args"]
                .as_array()?
                .iter()
                .map(decode)
                .collect::<Result<Vec<_>>>()
                .ok()?;
            (fingerprint(&serde_json::to_vec(&args).ok()?) == candidate.source_fingerprint)
                .then(|| args.first().cloned())
                .flatten()
        })
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
        if args.first() != Some(&source_key)
            || args.first().is_none_or(|key| !selector.key.matches(key))
        {
            continue;
        }
        decode(&event["response"])?;
        for (index, field) in &command.argument_values {
            let bytes = args
                .get(*index)
                .context("source selected argument missing")?;
            match field {
                config::ArgumentRule::Time(_) => {
                    super::redis::number(&serde_json::from_slice(bytes)?)?;
                }
                config::ArgumentRule::Json(fields) => {
                    let json = crate::replay::json_order::parse(bytes)
                        .context("source JSON request incomplete")?;
                    for (pointer, field) in &fields.json {
                        let value = json
                            .pointer(pointer)
                            .context("source selected JSON field missing")?;
                        match field {
                            config::JsonField::Time(_) => {
                                super::redis::number(value)?;
                            }
                            config::JsonField::Jwt(_) => {
                                ensure!(value.is_string(), "source JWT field must be a string");
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
