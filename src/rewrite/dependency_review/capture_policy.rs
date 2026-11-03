//! Compare sealed per-Case lifecycle receipts without reading business payloads.
use crate::dependency::observation::{MANIFEST_FILE, RECORDING_SCHEMA, RecordingManifest};
use crate::dependency_index::FileStamp;
use crate::policy::{AsyncRuleProvenance, AsyncTerminalProvenance, CompiledPolicy};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};

const OBSERVATION_FILE: &str = "async-api-observation.json";
const MAX_OBSERVATION_BYTES: u64 = 64 * 1024;
const MAX_RETURNED_GROUPS: usize = 64;

#[derive(Deserialize)]
struct Observation {
    api: String,
    scenario_index: Option<usize>,
    policy_provenance: Option<Value>,
}

#[derive(Clone, Serialize)]
struct Comparison {
    api: String,
    scenario_index: Option<usize>,
    status: &'static str,
    scenario_status: &'static str,
    unknown_reason: Option<&'static str>,
    recorded_rule_fingerprint: Option<String>,
    current_rule_fingerprint: Option<String>,
    recorded_scenario_fingerprint: Option<String>,
    current_scenario_fingerprint: Option<String>,
    recorded_terminals: Vec<AsyncTerminalProvenance>,
    current_terminals: Vec<AsyncTerminalProvenance>,
    cases: usize,
}

pub(super) fn information(
    state: &crate::rewrite::model::RewriteState,
    policy: &CompiledPolicy,
) -> Result<Value> {
    let source = state
        .case_source
        .as_deref()
        .context("Source recording absent")?;
    let root = crate::dependency_index::recording::root(source)
        .context("lifecycle provenance requires a sealed recording manifest")?;
    let manifest_path = root.join(MANIFEST_FILE);
    let stamp = FileStamp::read_native(&manifest_path)?;
    let manifest: RecordingManifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    ensure!(
        manifest.schema == RECORDING_SCHEMA
            && manifest.sealed
            && manifest.run_id == state.recording_run_id,
        "lifecycle provenance Source recording identity changed"
    );
    let root = fs::canonicalize(root)?;
    let files = manifest
        .files
        .iter()
        .map(|identity| (Path::new(&identity.path), identity))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        files.len() == manifest.files.len(),
        "recording manifest repeats a file identity"
    );
    let mut grouped = BTreeMap::<String, Comparison>::new();
    let mut input_ids = BTreeSet::new();
    let mut observations = 0;
    let mut inputs = 0;
    for input in manifest.inputs.iter().filter(|input| input.complete) {
        ensure!(
            input_ids.insert(input.case_id),
            "recording manifest repeats a complete input"
        );
        inputs += 1;
        let relative = Path::new(&input.path).join(OBSERVATION_FILE);
        let Some(identity) = files.get(relative.as_path()) else {
            // Absence is not proof that this input selected an async scenario.
            continue;
        };
        ensure!(
            !relative.is_absolute()
                && relative
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "lifecycle observation path escapes its recording"
        );
        let path = root.join(&relative);
        ensure!(
            fs::canonicalize(&path)?.starts_with(&root),
            "lifecycle observation resolves outside its recording"
        );
        ensure!(
            identity.length <= MAX_OBSERVATION_BYTES,
            "lifecycle observation exceeds its metadata budget"
        );
        let file_stamp = FileStamp::read_native(&path)?;
        ensure!(
            file_stamp.size == identity.length,
            "lifecycle observation length changed"
        );
        let mut bytes = Vec::with_capacity(identity.length as usize);
        fs::File::open(&path)?
            .take(MAX_OBSERVATION_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == identity.length
                && crate::policy_evidence::digest(&bytes).trim_start_matches("sha256:")
                    == identity.sha256.trim_start_matches("sha256:"),
            "lifecycle observation differs from its sealed identity"
        );
        ensure!(
            FileStamp::read_native(&path)? == file_stamp,
            "lifecycle observation changed during comparison"
        );
        let observation: Observation = serde_json::from_slice(&bytes)?;
        let mut comparison = compare(observation, policy)?;
        let key = serde_json::to_string(&comparison)?;
        if let Some(group) = grouped.get_mut(&key) {
            group.cases += 1;
        } else {
            comparison.cases = 1;
            grouped.insert(key, comparison);
        }
        observations += 1;
    }
    ensure!(
        FileStamp::read_native(&manifest_path)? == stamp,
        "recording manifest changed during lifecycle comparison"
    );
    let total = grouped.len();
    let groups = grouped
        .into_values()
        .take(MAX_RETURNED_GROUPS)
        .collect::<Vec<_>>();
    Ok(json!({
        "recorded_capture_policy_identity":manifest.capture_policy_identity,
        "complete_inputs":inputs,"inputs_with_async_observation":observations,
        "inputs_without_async_observation":inputs-observations,
        "groups":{"total":total,"returned":groups.len(),"omitted":total-groups.len(),"items":groups},
        "meaning":"Declaration identity comparison only. Missing provenance is unknown; a different rule does not establish policy application time, and a matching rule does not prove capture completeness or ownership."
    }))
}

fn compare(mut observation: Observation, policy: &CompiledPolicy) -> Result<Comparison> {
    ensure!(
        observation.api.len() <= 1200
            && observation.api.parse::<crate::RecordingApi>().is_ok()
            && observation.scenario_index.is_none_or(|index| index < 32),
        "lifecycle observation has invalid API/scenario metadata"
    );
    let current_rules = policy.async_api.get(&observation.api);
    let current = current_rules.and_then(|rules| {
        AsyncRuleProvenance::selected(&observation.api, rules, observation.scenario_index?)
    });
    let mut result = Comparison {
        api: observation.api.clone(),
        scenario_index: observation.scenario_index,
        status: "unknown",
        scenario_status: "unknown",
        unknown_reason: Some("recorded_rule_provenance_unavailable"),
        recorded_rule_fingerprint: None,
        current_rule_fingerprint: current_rules.map(crate::policy::async_rules_fingerprint),
        recorded_scenario_fingerprint: None,
        current_scenario_fingerprint: current
            .as_ref()
            .map(|item| item.scenario_fingerprint.clone()),
        recorded_terminals: vec![],
        current_terminals: current
            .as_ref()
            .map(|item| item.terminals.clone())
            .unwrap_or_default(),
        cases: 0,
    };
    let Some(raw) = observation
        .policy_provenance
        .take()
        .filter(|value| !value.is_null())
    else {
        return Ok(result);
    };
    if raw.get("version").and_then(Value::as_u64) != Some(1) {
        result.unknown_reason = Some("unsupported_recorded_provenance_version");
        return Ok(result);
    }
    let recorded: AsyncRuleProvenance = serde_json::from_value(raw)?;
    validate(&recorded, &observation)?;
    if current.as_ref().is_some_and(|current| {
        current.rule_fingerprint == recorded.rule_fingerprint
            && (current.scenario_fingerprint != recorded.scenario_fingerprint
                || current.terminals != recorded.terminals)
    }) {
        anyhow::bail!("recorded lifecycle scenario contradicts its effective rule identity");
    }
    result.status = match &result.current_rule_fingerprint {
        Some(current) if current == &recorded.rule_fingerprint => "same_rule",
        Some(_) => "different_rule",
        None => "current_rule_absent",
    };
    result.scenario_status = match &result.current_scenario_fingerprint {
        Some(current) if current == &recorded.scenario_fingerprint => {
            "same_scenario_at_recorded_index"
        }
        Some(_) => "different_scenario_at_recorded_index",
        None => "current_scenario_absent",
    };
    result.unknown_reason = None;
    result.recorded_rule_fingerprint = Some(recorded.rule_fingerprint);
    result.recorded_scenario_fingerprint = Some(recorded.scenario_fingerprint);
    result.recorded_terminals = recorded.terminals;
    Ok(result)
}

fn validate(recorded: &AsyncRuleProvenance, observation: &Observation) -> Result<()> {
    let fingerprint = |value: &str| {
        value.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    };
    ensure!(
        recorded.rule_id == format!("{}:{}", crate::policy::ASYNC_API_ID, observation.api)
            && Some(recorded.scenario_index) == observation.scenario_index
            && fingerprint(&recorded.rule_fingerprint)
            && fingerprint(&recorded.scenario_fingerprint)
            && (1..=32).contains(&recorded.terminals.len())
            && recorded.terminals.iter().all(|terminal| {
                fingerprint(&terminal.selector_fingerprint)
                    && terminal
                        .occurrence
                        .is_none_or(|count| (1..=1024).contains(&count))
            }),
        "recorded lifecycle policy provenance is inconsistent"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
