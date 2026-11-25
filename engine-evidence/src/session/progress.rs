//! Project fully replayed primary exchanges onto the existing public progress schema.

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use traffic_model::{session::SessionEvent, trace::RecordedEvent};

use crate::{
    config::api_catalog::{self, ApiCatalog},
    path_pattern::matches_path_pattern,
    verification_progress::{
        ApiObservation, EVENT_SESSION_RUN_PREFIX, LatestCounts, ProgressObservation,
        ProgressReport, VerificationStage, fingerprint, load, lock_publication, write,
    },
};

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SessionApiCounts {
    pub recorded: u64,
    pub verified: u64,
}

pub fn api_counts(
    target_root: &Path,
    recording_root: &Path,
    verified_through: Option<u64>,
) -> Result<BTreeMap<String, SessionApiCounts>> {
    let patterns = ApiCatalog::load(&target_root.join(api_catalog::PATH))?
        .unwrap_or_default()
        .case_paths();
    project_counts(
        traffic_recording_store::session::read(recording_root)?,
        &patterns,
        verified_through,
    )
}

fn project_counts(
    events: impl IntoIterator<Item = RecordedEvent<SessionEvent>>,
    patterns: &[String],
    verified_through: Option<u64>,
) -> Result<BTreeMap<String, SessionApiCounts>> {
    let mut apis = BTreeMap::<_, SessionApiCounts>::new();
    let mut primary = HashMap::new();
    for row in events {
        match row.event {
            SessionEvent::PrimaryRequest { exchange, request }
                if request["_session_probe"] != true =>
            {
                let method = request["method"]
                    .as_str()
                    .context("missing primary HTTP method")?;
                let uri = request["uri"]
                    .as_str()
                    .context("missing primary HTTP URI")?;
                let uri: hyper::Uri = uri.parse().context("invalid recorded primary HTTP URI")?;
                let path = uri.path();
                let selector = patterns
                    .iter()
                    .find(|pattern| matches_path_pattern(pattern, path))
                    .map_or(path, String::as_str);
                let api = format!("{method} {selector}");
                apis.entry(api.clone()).or_default().recorded += 1;
                primary.insert(exchange, api);
            }
            SessionEvent::PrimaryResponseEnd { exchange }
            | SessionEvent::PrimaryCancel { exchange, .. }
                if verified_through.is_some_and(|verified| row.sequence <= verified) =>
            {
                if let Some(api) = primary.remove(&exchange) {
                    apis.get_mut(&api).expect("recorded API exists").verified += 1;
                }
            }
            _ => {}
        }
    }
    Ok(apis)
}

/// A complete, strictly matched session contributes one logical regression.
pub fn publish_passed_progress(
    target_root: &Path,
    recording_root: &Path,
    apis: &BTreeMap<String, SessionApiCounts>,
) -> Result<bool> {
    if apis.is_empty() {
        return Ok(false);
    }
    ensure!(
        apis.values()
            .all(|counts| counts.recorded == counts.verified),
        "passing session does not cover every recorded API exchange"
    );
    let (_, manifest) = traffic_recording_store::source::recording::manifest(recording_root)?;
    let path = target_root.join(".traffic-e2e/progress.yaml");
    let _lock = lock_publication(&path)?;
    let mut report = load(&path, VerificationStage::Progress)?
        .unwrap_or_else(|| ProgressReport::new(VerificationStage::Progress));
    let key = format!("{EVENT_SESSION_RUN_PREFIX}{}", manifest.run_id);
    if report.counted_runs.contains_key(&key) {
        if report.requires_persistence() {
            write(&path, &report)?;
        }
        return Ok(false);
    }
    let observation = ProgressObservation {
        evidence_fingerprint: fingerprint(&serde_json::to_vec(&(
            &key,
            manifest.run_epoch,
            &manifest.files,
            apis,
        ))?),
        key,
        finished_at: chrono::Utc::now().to_rfc3339(),
        finalized: true,
        passed: Some(true),
        success_streak: None,
        apis: apis
            .iter()
            .map(|(api, counts)| {
                (
                    api.clone(),
                    ApiObservation {
                        cases: LatestCounts {
                            executed: counts.recorded,
                            passed: counts.verified,
                        },
                        finalized: true,
                        passed: true,
                        success_streak: None,
                    },
                )
            })
            .collect(),
    };
    let applied = report.apply(observation)?;
    if applied || report.requires_persistence() {
        write(&path, &report)?;
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use traffic_model::recording::{
        COMPACT_RECORDING_SCHEMA, MANIFEST_FILE, RecordingManifest, SourceArtifactIdentity,
    };
    use uuid::Uuid;

    use super::*;

    #[test]
    fn pending_exchanges_and_readiness_probes_do_not_pass_as_apis() {
        let (probe, first, second) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let events = [
            SessionEvent::PrimaryRequest {
                exchange: probe,
                request: json!({"method":"GET", "uri":"/api/ready", "_session_probe":true}),
            },
            SessionEvent::PrimaryRequest {
                exchange: first,
                request: json!({"method":"GET", "uri":"/api/items/1?view=summary"}),
            },
            SessionEvent::PrimaryRequest {
                exchange: second,
                request: json!({"method":"GET", "uri":"/api/items/2"}),
            },
            SessionEvent::PrimaryResponseEnd { exchange: first },
            SessionEvent::PrimaryResponseEnd { exchange: probe },
            SessionEvent::PrimaryResponseEnd { exchange: second },
        ]
        .into_iter()
        .enumerate()
        .map(|(index, event)| RecordedEvent {
            sequence: index as u64 + 1,
            offset_micros: 0,
            event,
        });
        let counts = project_counts(events, &["/api/items/*".into()], Some(5)).unwrap();
        assert_eq!(counts.len(), 1);
        assert_eq!(counts["GET /api/items/*"].recorded, 2);
        assert_eq!(counts["GET /api/items/*"].verified, 1);
    }

    #[tokio::test]
    async fn a_passing_recording_is_counted_once_across_retries_and_legacy_epochs() {
        let target = tempfile::tempdir().unwrap();
        let recording = tempfile::tempdir().unwrap();
        let run_epoch = Uuid::new_v4();
        let process_epoch = Uuid::new_v4();
        traffic_recording_store::writer::LedgerFiles::initialize(
            recording.path(),
            run_epoch,
            process_epoch,
        )
        .await
        .unwrap();
        let manifest = RecordingManifest {
            schema: COMPACT_RECORDING_SCHEMA.into(),
            run_id: "20261123161021".into(),
            run_epoch,
            process_epochs: vec![process_epoch],
            capture_policy_identity: "test".into(),
            source_artifact: SourceArtifactIdentity::Unavailable {
                reason: "test".into(),
            },
            sealed: true,
            capture_complete: true,
            coverage: Default::default(),
            records: 0,
            unattributed_records: 0,
            semantic_inventory: Default::default(),
            inputs: Vec::new(),
            files: Vec::new(),
        };
        fs::write(
            recording.path().join(MANIFEST_FILE),
            serde_json::to_vec(&manifest.archive()).unwrap(),
        )
        .unwrap();
        let path = target.path().join(".traffic-e2e/progress.yaml");
        let history_api = "GET /historical".to_owned();
        let session_api = "GET /items".to_owned();
        crate::verification_progress::record_completed_batch(
            &path,
            "20261123160900",
            chrono::Utc::now().to_rfc3339(),
            BTreeMap::from([(history_api.clone(), 1)]),
        )
        .unwrap();
        let counts = BTreeMap::from([(
            session_api.clone(),
            SessionApiCounts {
                recorded: 2,
                verified: 2,
            },
        )]);
        assert!(publish_passed_progress(target.path(), recording.path(), &counts).unwrap());
        assert!(!publish_passed_progress(target.path(), recording.path(), &counts).unwrap());
        let previously_published = fs::read(&path).unwrap();
        let updated_catalog_counts =
            BTreeMap::from([("GET /items/*".to_owned(), counts[&session_api])]);
        assert!(
            !publish_passed_progress(target.path(), recording.path(), &updated_catalog_counts)
                .unwrap()
        );
        assert_eq!(fs::read(&path).unwrap(), previously_published);

        crate::verification_progress::begin_epoch(target.path(), "20261123161100").unwrap();
        assert!(!publish_passed_progress(target.path(), recording.path(), &counts).unwrap());

        let report = load(&path, VerificationStage::Progress).unwrap().unwrap();
        assert_eq!(report.totals.runs.executed, 2);
        assert_eq!(report.totals.runs.passed, 1);
        assert_eq!(report.apis[&history_api].totals.cases.executed, 1);
        assert_eq!(report.apis[&session_api].totals.cases.executed, 2);
        assert_eq!(report.apis[&session_api].totals.cases.passed, 2);
    }
}
