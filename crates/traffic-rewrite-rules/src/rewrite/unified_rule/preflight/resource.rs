//! Complete resource scope is independent of the API that owns the issue.
//! Foreign executions retain their own protected clocks, reports and absence.
use super::*;
use crate::policy::NativeDomain;
use crate::rewrite::unified_rule::manifest::Artifact;
use crate::rewrite::unified_rule::manifest::ArtifactMethods;
use std::path::PathBuf;

pub use traffic_rewrite_model::rewrite::unified_rule::preflight::resource::ResourceRecord;

pub fn selected(policy: &CompiledPolicy, ids: &BTreeSet<String>) -> BTreeSet<String> {
    policy
        .native
        .iter()
        .filter(|r| {
            ids.contains(&r.rule.id)
                && r.domain == NativeDomain::Runtime
                && (r.rule.selector.resource.is_some()
                    || matches!(r.rule.effect, NativeEffect::RedisActivityRefresh(_)))
                && r.rule.selector.api.is_none()
                && !source::owns(r)
        })
        .map(|r| r.rule.id.clone())
        .chain(
            ids.iter()
                .filter(|id| {
                    (id.as_str() == crate::policy::GLOBAL_JSON_ID && policy.global_json.is_some())
                        || (id.as_str() == crate::value_contract::time::automatic::RULE_ID
                            && policy.global_json.is_some())
                        || (id.as_str() == "global.mysql" && policy.mysql.is_some())
                        || (id.as_str() == "global.redis" && policy.redis.is_some())
                        || (id.as_str() == crate::policy::GLOBAL_HTTP_ID && policy.http.is_some())
                        || (id.as_str() == crate::policy::ASYNC_API_ID
                            && !policy.async_api.is_empty())
                })
                .cloned(),
        )
        .collect()
}

fn context(root: &Path, source: &Path) -> crate::E2eRunContext {
    crate::E2eRunContext {
        target_root: root.into(),
        case_source: source.into(),
        run_key: None,
    }
}

fn execution_paths(
    root: &Path,
    source: &Path,
    api: &str,
) -> Result<(Option<[PathBuf; 4]>, Option<PathBuf>)> {
    traffic_rewrite_runtime::ensure_not_replaying(root, api)?;
    use crate::e2e_run::OptionalResponseRuleEvidence;
    match crate::e2e_run::optional_response_rule_evidence(context(root, source), api)? {
        OptionalResponseRuleEvidence::Absent => Ok((None, None)),
        OptionalResponseRuleEvidence::Unavailable(state) => Ok((None, Some(state))),
        OptionalResponseRuleEvidence::Available(e, state) => {
            Ok((Some([e.replay, e.assertions, e.aggregate, state]), None))
        }
    }
}

fn groups(index: Option<&Path>, source: &Path) -> Result<BTreeMap<String, String>> {
    let Some(index) = index else {
        return Ok(BTreeMap::new());
    };
    let inventory = crate::case_group::load_case_group_inventory(index, source)?;
    let mut groups = BTreeMap::new();
    for group in inventory.groups {
        for case in group.cases {
            ensure!(
                groups
                    .insert(case.case_id, group.group_id.clone())
                    .is_none(),
                "resource Source case belongs to multiple prepared APIs"
            );
        }
    }
    Ok(groups)
}

pub trait ResourceRecordMethods: Sized {
    fn ensure_current(&self, root: &Path, validation: Option<std::time::SystemTime>) -> Result<()>;
}

impl ResourceRecordMethods for ResourceRecord {
    fn ensure_current(&self, root: &Path, validation: Option<std::time::SystemTime>) -> Result<()> {
        if let Some(validation) = validation {
            crate::dependency_index::evidence::verify_frozen(
                &self.case_source,
                &self.snapshot,
                validation,
            )
            .context(
                "complete resource Source inventory changed after planning; recover and replan",
            )?;
        } else {
            ensure!(
                crate::dependency_index::evidence::prepare(&self.case_source)? == self.snapshot,
                "complete resource Source inventory changed after planning; recover and replan"
            );
        }
        let current = groups(self.inventory_path.as_deref(), &self.case_source)?;
        for (case, group) in &self.case_groups {
            ensure!(
                current.get(case).map(String::as_str).unwrap_or("") == group,
                "resource Source API membership changed after planning"
            );
        }
        for (api, evidence) in &self.executions {
            let (current, unavailable) = execution_paths(root, &self.case_source, api)?;
            let same_paths = match (&current, evidence) {
                (None, None) => true,
                (Some(paths), Some(evidence)) => paths
                    .iter()
                    .eq(evidence.iter().map(|artifact| &artifact.path)),
                _ => false,
            };
            ensure!(
                same_paths
                    && unavailable.as_ref()
                        == self
                            .unavailable_executions
                            .get(api)
                            .map(|artifact| &artifact.path),
                "resource Target execution changed after planning; obtain fresh evidence"
            );
        }
        Ok(())
    }
}

/// Keep complete envelopes and traces for matching cases. Native preselection
/// retains related reads and mutations; the Source session proves exact slots.
fn matches(policy: &CompiledPolicy, ids: &BTreeSet<String>, event: &Value) -> Result<bool> {
    let protocol = dependency::protocol(event);
    for rule in policy.native.iter().filter(|r| ids.contains(&r.rule.id)) {
        // Key-only refresh permissions must see every Redis Case to exclude
        // foreign writers and scripts on each discovered physical resource.
        if matches!(rule.rule.effect, NativeEffect::RedisActivityRefresh(_))
            && rule.rule.selector.resource.is_none()
            && protocol == Some(Protocol::Redis)
        {
            return Ok(true);
        }
        if matches!(rule.rule.effect, NativeEffect::HttpRequest(_))
            && (rule
                .rule
                .selector
                .operation
                .as_deref()
                .is_some_and(|method| event["method"].as_str() != Some(method))
                || rule.rule.selector.path.as_deref().is_some_and(|path| {
                    !event["uri"]
                        .as_str()
                        .and_then(|raw| raw.parse::<hyper::Uri>().ok())
                        .is_some_and(|uri| {
                            crate::path_pattern::matches_path_pattern(path, uri.path())
                        })
                }))
        {
            continue;
        }
        let resources = rule
            .rule
            .selector
            .resource
            .iter()
            .chain(match &rule.rule.effect {
                NativeEffect::Identity(effect) => effect
                    .references
                    .iter()
                    .map(|r| &r.contract.resource)
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            });
        for resource in resources {
            let endpoint = if protocol == Some(Protocol::Http) {
                let uri = event["uri"]
                    .as_str()
                    .and_then(|u| u.parse::<hyper::Uri>().ok());
                event["authority"]
                    .as_str()
                    .and_then(|raw| raw.parse::<hyper::http::uri::Authority>().ok())
                    .or_else(|| uri.as_ref().and_then(|u| u.authority().cloned()))
                    .map(|authority| {
                        let https = event["scheme"]
                            .as_str()
                            .is_some_and(|s| s.contains("https"))
                            || uri.as_ref().and_then(|u| u.scheme_str()) == Some("https");
                        (
                            authority.host().to_owned(),
                            authority.port_u16().unwrap_or(if https { 443 } else { 80 }),
                        )
                    })
            } else {
                event["target_host"]
                    .as_str()
                    .zip(event["target_port"].as_u64())
                    .and_then(|(host, port)| Some((host.to_owned(), u16::try_from(port).ok()?)))
            };
            if protocol == Some(resource.protocol)
                && resource
                    .database
                    .as_ref()
                    .is_none_or(|database| match database {
                        crate::policy::Database::Index(index) => {
                            event["database"].as_i64() == Some(*index)
                        }
                        crate::policy::Database::Name(name) => {
                            event["database"].as_str() == Some(name)
                        }
                    })
                && resource
                    .username
                    .as_deref()
                    .is_none_or(|name| event["username"].as_str() == Some(name))
                && endpoint.is_some_and(|(host, port)| {
                    host.eq_ignore_ascii_case(&resource.endpoint.host)
                        && port == resource.endpoint.port
                })
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn prepare(
    root: &Path,
    state: &RewriteState,
    bundle: &mut Bundle,
    policy: &CompiledPolicy,
    ids: &BTreeSet<String>,
) -> Result<(Option<ResourceRecord>, Vec<Bundle>)> {
    let ids = selected(policy, ids);
    if ids.is_empty() {
        return Ok((None, Vec::new()));
    }
    let case_source = state
        .case_source
        .as_ref()
        .context("resource rule has no Source scope")?;
    let (recording, files) = crate::dependency_index::recording_files(case_source)?;
    ensure!(
        files.len() <= 100_000,
        "resource Source case inventory exceeds bounds"
    );
    let snapshot = crate::dependency_index::evidence::prepare(&recording)?;
    bundle.freeze(&snapshot.path)?;
    let prepared = groups(bundle.inventory_path.as_deref(), case_source)?;
    let mut record = ResourceRecord {
        case_source: case_source.clone(),
        snapshot,
        inventory_path: bundle.inventory_path.clone(),
        case_groups: BTreeMap::new(),
        affected_apis: BTreeSet::new(),
        executions: BTreeMap::new(),
        unavailable_executions: BTreeMap::new(),
    };
    let mut foreign: BTreeMap<String, BTreeMap<String, PathBuf>> = BTreeMap::new();
    for file in files {
        let mut hit = ids.contains(crate::policy::GLOBAL_JSON_ID)
            || ids.contains(crate::value_contract::time::automatic::RULE_ID)
            || ids.contains("global.mysql")
            || ids.contains("global.redis")
            || ids.contains(crate::policy::GLOBAL_HTTP_ID)
            || ids.contains(crate::policy::ASYNC_API_ID);
        crate::dependency_index::proof::visit(
            &file,
            |_| Ok(true),
            |event| {
                hit |= matches(policy, &ids, event)?;
                Ok(())
            },
        )?;
        if !hit {
            continue;
        }
        let directory = file.parent().context("resource case has no directory")?;
        let case = directory
            .file_name()
            .and_then(|n| n.to_str())
            .context("invalid resource Case id")?;
        let request = bundle.request(&directory.join("request.json"))?;
        let method = request["method"]
            .as_str()
            .context("resource Source method is absent")?;
        let uri: hyper::Uri = request["uri"]
            .as_str()
            .context("resource Source URI is absent")?
            .parse()?;
        let api = prepared.get(case).cloned().unwrap_or_else(|| {
            format!(
                "{method} {}",
                request["api_pattern"].as_str().unwrap_or(uri.path())
            )
        });
        record
            .case_groups
            .insert(case.into(), prepared.get(case).cloned().unwrap_or_default());
        record.affected_apis.insert(api.clone());
        if !bundle.cases.contains_key(case) {
            bundle.freeze(&file)?;
            bundle.primary_response(case, directory)?;
            foreign
                .entry(api)
                .or_default()
                .insert(case.into(), directory.into());
        }
    }
    let mut output = Vec::new();
    for (api, cases) in foreign {
        let (evidence, unavailable) = execution_paths(root, case_source, &api)?;
        let evidence = evidence
            .map(|paths| {
                paths
                    .iter()
                    .map(|path| Artifact::capture(path))
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?;
        let unavailable = unavailable.as_deref().map(Artifact::capture).transpose()?;
        let mut other = Bundle {
            inventory_path: bundle.inventory_path.clone(),
            replay_path: bundle.replay_path.clone(),
            replay: Value::Null,
            assertions: Value::Null,
            cases,
            artifacts: BTreeMap::new(),
        };
        if let Some(unavailable) = unavailable {
            unavailable
                .verify()
                .context("unfinished foreign Replay changed while planning")?;
            other
                .artifacts
                .insert(unavailable.path.clone(), unavailable.clone());
            record
                .unavailable_executions
                .insert(api.clone(), unavailable);
        }
        if let Some(artifacts) = &evidence {
            for artifact in artifacts {
                artifact.verify()?;
                other
                    .artifacts
                    .insert(artifact.path.clone(), artifact.clone());
            }
            let replay = other.json(&artifacts[0].path)?;
            // Old-policy executions are explicitly unavailable for this plan;
            // their identities stay frozen and genuine Replay remains required.
            if replay["replay_policy"]["fingerprint"]
                == bundle.replay["replay_policy"]["fingerprint"]
            {
                ensure!(
                    replay["finalized"] == true,
                    "foreign resource Replay is incomplete"
                );
                other.replay_path = artifacts[0].path.clone();
                other.replay = replay;
                other.assertions = other.json(&artifacts[1].path)?;
                let aggregate = other.json(&artifacts[2].path)?;
                ensure!(
                    aggregate["complete"] == true
                        && other.assertions["expected_response"] == "assertions_only"
                        && other.assertions["assertion_mode"] == "runner_owned"
                        && other.assertions["policy_fingerprint"]
                            == bundle.replay["replay_policy"]["fingerprint"],
                    "foreign resource evidence is incomplete or uses another policy"
                );
                for document in [&aggregate, &other.assertions] {
                    ensure!(
                        document["case_source"]
                            .as_str()
                            .map(Path::new)
                            .map(fs::canonicalize)
                            .transpose()?
                            .as_deref()
                            == Some(fs::canonicalize(case_source)?.as_path()),
                        "foreign resource evidence belongs to another recording scope"
                    );
                }
                for (case, dir) in other.cases.clone() {
                    ensure!(
                        other.replay["cases"]
                            .as_array()
                            .is_some_and(|rows| rows.iter().any(|row| row["case_id"] == case
                                && row["case_dir"] == dir.to_string_lossy().as_ref())),
                        "foreign resource Replay omits a matching Source case"
                    );
                    other.primary_response(&case, &dir)?;
                }
            }
        }
        record.executions.insert(api, evidence);
        output.push(other);
    }
    Ok((Some(record), output))
}
