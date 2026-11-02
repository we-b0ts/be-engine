//! Explicit bounded reads of authenticated actual Target requests, including run-owned I/O.
use super::model::SCHEMA;
use crate::{
    policy::{Protocol, Surface},
    policy_evidence::{TargetRole, WitnessManifest},
    rewrite::{RewriteContext, model::RewriteState},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};

fn context(root: &Path, state: &RewriteState) -> Result<crate::E2eRunContext> {
    Ok(crate::E2eRunContext {
        target_root: root.into(),
        case_source: state
            .case_source
            .clone()
            .or_else(|| state.recording_input_case_source.clone())
            .or_else(|| {
                let path = crate::rewrite::artifacts::recording_run(root, &state.recording_run_id);
                path.is_dir().then_some(path)
            })
            .context("Source absent")?,
        run_key: None,
    })
}

pub(super) fn inventory(root: &Path, state: &RewriteState, offset: usize) -> Result<Value> {
    let reference = crate::e2e_run::batch_diagnostic_report(context(root, state)?, None)?;
    let bytes = fs::read(&reference.path)?;
    let report: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        report["version"] == 7 && report["session_id"].as_str() == Some(&reference.session_id),
        "actual batch report identity differs"
    );
    let manifest: WitnessManifest = serde_json::from_value(report["policy_witnesses"].clone())?;
    let graph = manifest
        .graph()
        .context("actual batch has no independent Target observation graph")?;
    ensure!(
        graph
            .replay
            .as_ref()
            .is_some_and(|binding| binding.session_id == reference.session_id),
        "Target graph belongs to another actual session"
    );
    let targets = graph
        .targets
        .iter()
        .filter(|target| {
            target.metadata.role == TargetRole::IndependentTargetObservation
                && target.metadata.surface == Surface::DependencyRequest
        })
        .collect::<Vec<_>>();
    let entries=targets.iter().skip(offset).take(20).map(|target|{
        let pointer=match target.metadata.resource.as_ref().map(|resource|resource.protocol) {Some(Protocol::Redis)=>"/args/0",Some(Protocol::Mysql)=>"/sql",Some(Protocol::Http)=>"/method",_=>"/command"};
        json!({"target_observation_id":target.id,"metadata":target.metadata,
        "query_command":crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"target".into(),"--session".into(),reference.session_id.clone(),"--observation".into(),target.id.clone(),"--pointer".into(),pointer.into()],vec![])})}).collect::<Vec<_>>();
    Ok(
        json!({"actual_session_id":reference.session_id,"actual_round":reference.sequence,"report_sha256":crate::policy_evidence::digest(&bytes),
        "total":targets.len(),"offset":offset,"items":entries,"coverage_complete":manifest.complete && manifest.sealed,
        "coverage_error":report["target_observation_coverage_error"],"hypothesis_coverage_error":report["dependency_hypothesis_coverage_error"],
        "next_command":(offset.saturating_add(20)<targets.len()).then(||crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"batch".into(),"--offset".into(),offset.saturating_add(20).to_string()],vec![])),
        "does_not_prove":"Metadata is an observation reference. The target query authenticates the selected encrypted blob; neither operation grants matching or ownership permission."}),
    )
}

pub fn dependency_attribution_target(
    context_options: RewriteContext,
    session: &str,
    observation: &str,
    pointer: &str,
) -> Result<Value> {
    ensure!(
        observation.len() <= 1024
            && pointer.starts_with('/')
            && pointer.len() > 1
            && pointer.len() <= 1024,
        "select a bounded actual Target identity and non-root pointer"
    );
    let (root, store) = super::open(&context_options.target_root)?;
    let state = store.load()?.context("rewrite workflow absent")?;
    let focused = state
        .group_id
        .as_deref()
        .zip(state.active_issue.as_ref().map(|issue| issue.attempt));
    let reference =
        crate::e2e_run::session_diagnostic_report(context(&root, &state)?, session, focused)?;
    let bytes = fs::read(&reference.path)?;
    let report: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        report["version"] == 7 && report["session_id"].as_str() == Some(session),
        "actual Target report belongs to another session"
    );
    let manifest: WitnessManifest = serde_json::from_value(report["policy_witnesses"].clone())?;
    let graph = manifest
        .graph()
        .context("actual Target observation graph absent")?;
    ensure!(
        graph
            .replay
            .as_ref()
            .is_some_and(|binding| binding.session_id == session),
        "actual Target graph belongs to another session"
    );
    let mut selected = graph
        .targets
        .iter()
        .enumerate()
        .filter(|(_, target)| target.id == observation);
    let (index, target) = selected
        .next()
        .context("Target identity is absent from this actual session")?;
    ensure!(selected.next().is_none(), "ambiguous Target identity");
    ensure!(
        target.metadata.role == TargetRole::IndependentTargetObservation
            && target.metadata.surface == Surface::DependencyRequest,
        "selected bytes are not an independent actual dependency request"
    );
    let artifact = crate::policy_evidence::artifact_path(&reference.path, &manifest)?;
    crate::dependency_index::FileStamp::read_native(&artifact)?;
    // Per-entry authentication permits diagnosis of retained observations when total
    // coverage is incomplete. Such a query never becomes a formal rule proof.
    let raw =
        crate::policy_evidence::read_target(&artifact, &manifest, index, &reference.key_context)?;
    let protocol = target
        .metadata
        .resource
        .as_ref()
        .map(|resource| resource.protocol);
    let value = select(&raw, protocol, pointer)?;
    let bounded = value
        .as_ref()
        .is_none_or(|value| serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= 4096));
    let selection_status = if !bounded {
        "too_large_select_a_narrower_pointer"
    } else if value.is_some() {
        "present"
    } else {
        "missing"
    };
    Ok(
        json!({"schema":SCHEMA,"actual_session_id":session,"actual_round":reference.sequence,"report_sha256":crate::policy_evidence::digest(&bytes),
        "target_observation_id":observation,"metadata":target.metadata,"pointer":pointer,
        "coverage_complete":manifest.complete && manifest.sealed,"coverage_error":report["target_observation_coverage_error"],
        "selected_value":if bounded{value}else{None},"selection_status":selection_status,
        "formal_rule_proof":false,"does_not_prove":"Authenticated actual Target bytes do not establish a Source owner, successful match, allowed rule or consumption."}),
    )
}

fn select(raw: &[u8], protocol: Option<Protocol>, pointer: &str) -> Result<Option<Value>> {
    if protocol == Some(Protocol::Redis)
        && let Some(rest) = pointer.strip_prefix("/args/")
    {
        let (index, suffix) = rest.split_once('/').unwrap_or((rest, ""));
        let index: usize = index.parse()?;
        ensure!(index < 128, "Redis argument selector exceeds bounds");
        let arguments: Vec<Vec<u8>> = serde_json::from_slice(raw)?;
        let Some(bytes) = arguments.get(index) else {
            return Ok(None);
        };
        if let Some(pointer) = suffix.strip_prefix("json/") {
            return Ok(crate::json_value::parse_with_limit(bytes, 1024 * 1024)
                .and_then(|value| value.pointer(&format!("/{pointer}")).cloned()));
        }
        if suffix.is_empty() || suffix == "text" {
            return Ok(std::str::from_utf8(bytes).ok().map(|text| json!(text)));
        }
        anyhow::bail!("Redis selection uses /args/<zero-based-index>[/text|/json/<pointer>]");
    }
    Ok(crate::json_value::parse_with_limit(raw, 4 * 1024 * 1024)
        .and_then(|value| value.pointer(pointer).cloned()))
}
