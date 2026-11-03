//! Authenticated reusable Source ownership, separate from per-inventory proofs.
use crate::{
    dependency::{attribution::DependencyOwner, observation::RecordingManifest},
    policy::AsyncApiRules,
    source_ownership::{self, CaseFacts, Outcome},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};
use uuid::Uuid;

#[cfg(test)]
mod tests;

#[derive(Default)]
pub(super) struct Materialized {
    pub owners: BTreeMap<Uuid, DependencyOwner>,
    pub policy_identity: Option<String>,
    pub diagnostic: Value,
}

#[derive(Serialize, Deserialize)]
struct Cached {
    key: String,
    outcome: Outcome,
    #[serde(default)]
    execution_unavailable: bool,
}

pub(super) fn load(source: &Path, target: Option<&Path>) -> Result<Materialized> {
    let Some(target) = target else {
        return Ok(Materialized::default());
    };
    let path = crate::rewrite::fingerprint::policy_file(target)?;
    if !path.is_file() {
        return Ok(Materialized::default());
    }
    let policy = crate::policy::parse_and_compile_policy(&fs::read_to_string(path)?)?;
    if !policy
        .async_api
        .values()
        .any(|rules| rules.iter().any(|rule| rule.ownership.is_some()))
    {
        return Ok(Materialized::default());
    }
    materialize(source, &policy.async_api)
}

pub(super) fn materialize(
    source: &Path,
    rules: &BTreeMap<String, AsyncApiRules>,
) -> Result<Materialized> {
    let (root, manifest) = crate::dependency_index::recording::manifest(source)?;
    let inventory = fs::read(root.join(crate::dependency::observation::MANIFEST_FILE))?;
    let policy_identity = crate::policy_evidence::digest(&serde_json::to_vec(&(
        "async-source-ownership-policy/v1",
        rules,
    ))?);
    let key = crate::policy_evidence::digest(&serde_json::to_vec(&(
        "async-source-ownership-materialization/v2",
        crate::build_info::ENGINE_FINGERPRINT,
        executor_identity(),
        crate::policy_evidence::digest(&inventory),
        &policy_identity,
    ))?);
    let cache_dir = crate::dependency_index::store::cache_directory(&root);
    crate::dependency_index::store::private_directory(&cache_dir)?;
    let cache = cache_dir.join(format!(
        "source-ownership-{}.json",
        key.trim_start_matches("sha256:")
    ));
    // Authentication is mandatory even when a derived result has been cached.
    crate::dependency_index::recording::authenticate(&root)?;
    let (outcome, execution_unavailable) =
        match crate::dependency_index::store::read_json::<Cached>(&cache) {
            Ok(cached) if cached.key == key => (cached.outcome, cached.execution_unavailable),
            _ => {
                let inputs = inputs(&root, &manifest)?;
                let mut input =
                    crate::dependency_index::RecordStream::open(&root.join("dependencies.jsonl"))?;
                let mut events = Vec::new();
                while let Some((_, bytes)) = input.next()? {
                    if bytes.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    let event: Value = serde_json::from_slice(bytes)?;
                    if let Some(event) = source_ownership::request_view(&event, rules) {
                        events.push(event);
                    }
                }
                let (outcome, execution_unavailable) =
                    match source_ownership::classify(rules, &inputs, &events) {
                        Ok(outcome) => (outcome, false),
                        Err(_) => {
                            // A broken automatic executor cannot restore the original
                            // time-window hypothesis as positive ownership authority.
                            // Independent per-occurrence proofs can still resolve this
                            // finite conservative set through ordinary apply.
                            let unresolved =
                                source_ownership::potential_occurrences(rules, &events);
                            (
                                Outcome {
                                    unresolved,
                                    ..Default::default()
                                },
                                true,
                            )
                        }
                    };
                crate::dependency_index::store::write_json(
                    &cache,
                    &Cached {
                        key: key.clone(),
                        outcome: outcome.clone(),
                        execution_unavailable,
                    },
                )?;
                (outcome, execution_unavailable)
            }
        };
    let mut owners = outcome
        .decisions
        .iter()
        .map(|(id, assignment)| {
            (
                *id,
                DependencyOwner::Case {
                    origin_case_id: assignment.case_id,
                    task_instance: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for id in &outcome.unresolved {
        owners.insert(
            *id,
            DependencyOwner::Unattributed {
                reason: if execution_unavailable {
                    "async_policy_execution_unavailable"
                } else {
                    "async_policy_origin_ambiguous"
                }
                .into(),
            },
        );
    }
    let diagnostic = serde_json::json!({
        "status": if execution_unavailable {"execution_unavailable"} else {"executed"},
        "policy_identity": policy_identity,
        "assigned_occurrences": outcome.decisions.len(),
        "problem_count": outcome.problems.len(),
        "unresolved_occurrences": outcome.unresolved.len(),
        "problems": outcome.problems.iter().take(16).collect::<Vec<_>>(),
        "omitted_problems": outcome.problems.len().saturating_sub(16),
        "manual_attribution_available": true,
        "recording_completion_proved": false,
    });
    Ok(Materialized {
        owners,
        policy_identity: Some(policy_identity),
        diagnostic,
    })
}

fn inputs(root: &Path, manifest: &RecordingManifest) -> Result<Vec<CaseFacts>> {
    let mut result = Vec::new();
    for input in manifest.inputs.iter().filter(|input| input.complete) {
        let directory = root.join(&input.path);
        let request = read(root, manifest, &directory.join("request.json"))?;
        let response = read(root, manifest, &directory.join("expected-response.json"))?;
        result.push(CaseFacts {
            case_id: input.case_id,
            method: request["method"]
                .as_str()
                .context("Source method absent")?
                .into(),
            uri: request["uri"].as_str().context("Source URI absent")?.into(),
            request: crate::replay::native_source_request_body(&request),
            request_unavailable: source_ownership::request_unavailable(&request),
            response: crate::replay::native_source_request_body(&response),
            started_at: serde_json::from_value(request["timestamp"].clone())
                .context("Source request clock absent")?,
        });
    }
    Ok(result)
}

fn read(root: &Path, manifest: &RecordingManifest, path: &Path) -> Result<Value> {
    let relative = path
        .strip_prefix(root)
        .context("Source input escapes recording")?;
    let identity = manifest
        .files
        .iter()
        .find(|file| Path::new(&file.path) == relative)
        .context("Source ownership input is not sealed")?;
    ensure!(
        fs::canonicalize(path)?.starts_with(fs::canonicalize(root)?),
        "Source input escapes recording"
    );
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() as u64 == identity.length
            && crate::policy_evidence::digest(&bytes).trim_start_matches("sha256:")
                == identity.sha256.trim_start_matches("sha256:"),
        "Source ownership input changed after recording seal"
    );
    serde_json::from_slice(&bytes).context("invalid Source input")
}

fn executor_identity() -> &'static str {
    static IDENTITY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    IDENTITY
        .get_or_init(|| {
            use sha2::{Digest, Sha256};
            let mut digest = Sha256::new();
            // A dirty development build can share its Git revision with an older
            // executor. Bind derived authority to the compiled implementation too.
            for source in [
                include_bytes!("../../source_ownership/mod.rs").as_slice(),
                include_bytes!("../../source_ownership/mysql.rs").as_slice(),
                include_bytes!("../../source_ownership/mysql/prepared.rs").as_slice(),
                include_bytes!("../../source_ownership/origins.rs").as_slice(),
                include_bytes!("../../source_ownership/projection.rs").as_slice(),
                include_bytes!("../../source_ownership/redis.rs").as_slice(),
                include_bytes!("../../source_ownership/transactions.rs").as_slice(),
                include_bytes!("../../policy/async_api/ownership.rs").as_slice(),
                include_bytes!("policy_ownership.rs").as_slice(),
            ] {
                digest.update(source.len().to_le_bytes());
                digest.update(source);
            }
            format!("sha256:{:x}", digest.finalize())
        })
        .as_str()
}
