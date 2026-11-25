//! Incremental counts published by the Session recorder.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use traffic_model::{
    recording::{RecordingManifest, SESSION_RECORDING_SCHEMA},
    session::SessionEvent,
};

use crate::source::{FileStamp, digest, recording};

pub const FILE: &str = "session-summary.json";
const LIVE_FILE: &str = "session-summary.live.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSummary {
    pub routes: Vec<SessionRouteSummary>,
    pub physical_events: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sequence: Option<u64>,
    pub primary_completed: u64,
    pub primary_cancelled: u64,
    pub successful_connections: u64,
    pub cancelled_output_starts: Vec<u64>,
    pub mandatory_by_protocol: BTreeMap<String, u64>,
    pub unscheduled_admissions: Vec<u64>,
    pub targets: Vec<SessionTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTarget {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRouteSummary {
    pub method: String,
    pub path: String,
    pub requests: u64,
    pub first_seq: u64,
}

#[derive(Default)]
pub(crate) struct CaptureSummary {
    routes: BTreeMap<(String, String), (u64, u64)>,
    physical_events: u64,
    last_sequence: Option<u64>,
    primary_completed: u64,
    primary_cancelled: u64,
    pub(crate) successful_connections: u64,
    pub(crate) cancelled_output_starts: BTreeSet<u64>,
    pub(crate) mandatory_by_protocol: BTreeMap<String, u64>,
    pub(crate) unscheduled_admissions: BTreeSet<u64>,
    pub(crate) targets: BTreeSet<SessionTarget>,
}

impl CaptureSummary {
    pub(crate) fn note_row(&mut self, sequence: u64) {
        self.physical_events += 1;
        self.last_sequence = Some(sequence);
    }

    pub(crate) fn observe(&mut self, sequence: u64, event: &SessionEvent) -> Result<()> {
        match event {
            SessionEvent::PrimaryRequest { request, .. }
                if request["_session_probe"].as_bool() != Some(true) =>
            {
                let method = request["method"]
                    .as_str()
                    .context("missing primary method")?;
                let uri = request["uri"].as_str().context("missing primary URI")?;
                let uri: http::Uri = uri.parse().context("invalid primary URI")?;
                let (requests, _) = self
                    .routes
                    .entry((method.to_owned(), uri.path().to_owned()))
                    .or_insert((0, sequence));
                *requests += 1;
            }
            SessionEvent::PrimaryResponseEnd { .. } => self.primary_completed += 1,
            SessionEvent::PrimaryCancel { .. } => self.primary_cancelled += 1,
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        let routes = self
            .routes
            .iter()
            .map(
                |((method, path), &(requests, first_seq))| SessionRouteSummary {
                    method: method.clone(),
                    path: path.clone(),
                    requests,
                    first_seq,
                },
            )
            .collect();
        let snapshot = SessionSummary {
            routes,
            physical_events: self.physical_events,
            last_sequence: self.last_sequence,
            primary_completed: self.primary_completed,
            primary_cancelled: self.primary_cancelled,
            successful_connections: self.successful_connections,
            cancelled_output_starts: self.cancelled_output_starts.iter().copied().collect(),
            mandatory_by_protocol: self.mandatory_by_protocol.clone(),
            unscheduled_admissions: self.unscheduled_admissions.iter().copied().collect(),
            targets: self.targets.iter().cloned().collect(),
        };
        let mut json = serde_json::to_vec(&snapshot)?;
        json.push(b'\n');
        Ok(json)
    }
}

pub fn read(root: &Path) -> Result<SessionSummary> {
    let (root, manifest) = recording::manifest(root)?;
    read_summary(&root, &manifest)
}

/// Return the final physical sequence in the sealed Source timeline.
pub fn recording_end_sequence(root: &Path) -> Result<Option<u64>> {
    let (root, manifest) = recording::manifest(root)?;
    if manifest.schema != SESSION_RECORDING_SCHEMA {
        return Ok(None);
    }
    if let Some(sequence) = read_summary(&root, &manifest)?.last_sequence {
        ensure!(sequence > 0, "sealed Session ends at an invalid sequence");
        return Ok(Some(sequence));
    }
    Ok(Some(crate::session_integrity::last_event_sequence(
        &root, &manifest,
    )?))
}

fn read_summary(root: &Path, manifest: &RecordingManifest) -> Result<SessionSummary> {
    let identity = manifest
        .files
        .iter()
        .find(|entry| entry.path == FILE)
        .context("recording has no sealed Session summary")?;
    let path = root.join(FILE);
    let stamp = FileStamp::read_native(&path)?;
    ensure!(
        stamp.size == identity.length,
        "Session summary length changed"
    );
    let bytes = std::fs::read(&path)?;
    ensure!(
        identity.sha256 == digest(&bytes) && FileStamp::read_native(&path)? == stamp,
        "sealed Session summary changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) async fn publish_live(root: &Path, summary: &CaptureSummary) -> Result<()> {
    let temp = root.join(".session-summary.live.json.tmp");
    crate::storage::write(&temp, &summary.bytes()?).await?;
    tokio::fs::rename(temp, root.join(LIVE_FILE)).await?;
    Ok(())
}

pub(crate) async fn remove_live(root: &Path) -> Result<()> {
    if let Err(error) = tokio::fs::remove_file(root.join(LIVE_FILE)).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error.into());
    }
    Ok(())
}
