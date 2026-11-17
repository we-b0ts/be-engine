//! Restore ordinary Case admission from finite original input/protocol evidence.
//! These are mechanical scope defaults, never authored Source proofs or delivery.
mod mysql;
use crate::dependency::{
    attribution::DependencyOwner,
    observation::{CaptureMetadata, CapturePhase},
};
use crate::dependency_index::{recording, store};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};
use uuid::Uuid;

pub fn load(source: &Path, target: Option<&Path>) -> Result<BTreeMap<Uuid, DependencyOwner>> {
    let (root, manifest) = recording::manifest(source)?;
    if manifest.semantic_inventory.unattributed_dependencies == 0 {
        return Ok(BTreeMap::new());
    }
    let process = target
        .and_then(|target| crate::execution_identity::policy_file(target).ok())
        .filter(|path| path.is_file())
        .map(|path| {
            let policy = crate::policy::parse_and_compile_policy(&fs::read_to_string(path)?)?;
            crate::config::native_policy::project_source_policy(&policy.native)
                .map(|policy| policy.process_owned_dependencies)
        })
        .transpose()?
        .unwrap_or_default();
    let key = crate::policy_evidence::digest(&serde_json::to_vec(&(
        "case-native-admission-ownership/v2",
        &manifest,
        &process,
    ))?);
    let directory = store::cache_directory(&root);
    let cache = directory.join(format!(
        "case-window-ownership-{}.json",
        key.trim_start_matches("sha256:")
    ));
    if let Ok(defaults) = store::read_json(&cache) {
        recording::authenticate(&root)?;
        return Ok(defaults);
    }
    // Only the small unowned view is read. A status query must not reconstruct
    // the complete central Source index just to admit ordinary Case traffic.
    let path = root.join("indexes/unattributed-scope.json");
    let mut input = crate::dependency_index::RecordStream::open(&path)?;
    let mut candidates = Vec::new();
    let mut mysql_events = Vec::new();
    while let Some((_, line)) = input.next()? {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let event: Value = serde_json::from_slice(line)?;
        if let Some(frame) = mysql::Frame::read(&event, None, &BTreeMap::new())? {
            mysql_events.push(frame);
        }
        if let Some(capture) = candidate(&event)?
            && !process.iter().any(|rule| {
                matches!(rule,
                    crate::config::BackgroundDependencyRuleConfig::RedisPubsub { selector, .. }
                    if crate::config::process_owned_dependencies::pubsub::matches_value(selector, &event))
            })
        {
            candidates.push(capture);
        }
    }
    if candidates.is_empty() && !mysql_events.iter().any(mysql::Frame::candidate) {
        return Ok(BTreeMap::new());
    }
    recording::authenticate(&root)?;
    store::private_directory(&directory)?;
    let mut windows = BTreeMap::new();
    for input in &manifest.inputs {
        if !input.complete {
            continue;
        }
        let directory = root.join(&input.path);
        let request = directory.join("request.json");
        let response = directory.join("expected-response.json");
        if ![&request, &response].iter().all(|path| {
            path.strip_prefix(&root).ok().is_some_and(|relative| {
                manifest
                    .files
                    .iter()
                    .any(|file| Path::new(&file.path) == relative)
            })
        }) {
            continue;
        }
        ensure!(
            fs::canonicalize(&directory)?.starts_with(fs::canonicalize(&root)?),
            "Case admission window escapes the sealed Source recording"
        );
        // Read physical capture clocks only. Response content never selects an
        // input or relaxes a request/value contract.
        let request: Value = serde_json::from_slice(&fs::read(request)?)?;
        let response: Value = serde_json::from_slice(&fs::read(response)?)?;
        if let (Some(start), Some(end)) = (timestamp(&request), timestamp(&response))
            && start <= end
        {
            windows.insert(input.case_id, (start, end));
        }
    }
    let mut defaults = BTreeMap::new();
    for capture in candidates {
        let case = capture
            .observed_case
            .context("candidate has an observed Case")?;
        if windows
            .get(&case)
            .is_some_and(|(start, end)| *start <= capture.started_at && capture.started_at <= *end)
        {
            let owner = DependencyOwner::Case {
                origin_case_id: case,
                task_instance: None,
            };
            if let Some(previous) = defaults.insert(capture.exchange_id, owner.clone()) {
                ensure!(previous == owner, "contradictory Case observation identity");
            }
        }
    }
    mysql::extend(&root, &manifest, &windows, mysql_events, &mut defaults)?;
    store::write_json(&cache, &defaults)?;
    Ok(defaults)
}

fn timestamp(value: &Value) -> Option<DateTime<Utc>> {
    serde_json::from_value(value.get("timestamp")?.clone()).ok()
}

fn candidate(event: &Value) -> Result<Option<CaptureMetadata>> {
    if event["event_type"] != "redis_pub_sub_push" || !event["rpc_request"].is_null() {
        return Ok(None);
    }
    let Some(value) = event.get("capture") else {
        return Ok(None);
    };
    let capture: CaptureMetadata = serde_json::from_value(value.clone())?;
    Ok((capture.phase == CapturePhase::Runtime
        && capture.observed_case.is_some()
        && capture.admitted_case.is_none()
        && capture.matched_rule_id.is_none()
        && capture.matched_rule_ids.is_empty()
        && capture.semantic_required
        && matches!(&capture.attribution, DependencyOwner::Unattributed { reason } if reason == "outside_admission"))
    .then_some(capture))
}
