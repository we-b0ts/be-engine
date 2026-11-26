//! Bounded lookup of primary request locations without reading response payloads.

use std::{
    io::{BufRead, BufReader},
    ops::RangeInclusive,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use traffic_model::recording::identity::IdentityKind;
use uuid::Uuid;

use super::{PrimaryEventKind, decode_document, parse_prefix, primary_kind};
use crate::{
    session_integrity,
    source::{recording, segment_window::SegmentWindow},
};

pub struct PrimaryRequestLocation {
    pub sequence: u64,
    pub offset_micros: u64,
    pub exchange: Uuid,
    pub route: PrimaryRoute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryRoute {
    pub method: String,
    pub path: String,
}

/// Return the first non-probe request whose route satisfies the selection.
pub fn first_primary_request(
    root: &Path,
    sequences: RangeInclusive<u64>,
    matches: impl Fn(&PrimaryRoute) -> bool,
) -> Result<Option<PrimaryRequestLocation>> {
    let (root, manifest) = recording::manifest(root)?;
    ensure!(
        manifest.capture_complete,
        "Source session capture is incomplete"
    );
    let mut input =
        BufReader::with_capacity(64 * 1024, session_integrity::events(&root, &manifest)?);
    let mut segments = SegmentWindow::new_copying(root).with_seal(&manifest);
    let mut row = Vec::new();
    let mut previous = (0, 0);
    let mut saw_source_start = false;
    while input.read_until(b'\n', &mut row)? != 0 {
        let (sequence, offset_micros, kind, fields) = parse_prefix(&row)?;
        ensure!(
            sequence > previous.0 && offset_micros >= previous.1,
            "unordered session event {sequence}"
        );
        previous = (sequence, offset_micros);
        if let Some(kind) = primary_kind(kind) {
            ensure!(
                saw_source_start || kind == PrimaryEventKind::SourceStart,
                "Source session does not start with a process launch"
            );
            saw_source_start = true;
            if kind == PrimaryEventKind::PrimaryRequest
                && sequences.contains(&sequence)
                && let Some(route) = read_primary_route(fields, &mut segments)?
                && matches(&route)
            {
                return Ok(Some(PrimaryRequestLocation {
                    sequence,
                    offset_micros,
                    exchange: IdentityKind::Case.bridge(manifest.run_epoch, sequence),
                    route,
                }));
            }
        }
        if sequence >= *sequences.end() {
            break;
        }
        row.clear();
    }
    ensure!(
        saw_source_start,
        "Source session does not start with a process launch"
    );
    Ok(None)
}

pub(super) fn read_primary_route(
    document: &[u8],
    segments: &mut SegmentWindow,
) -> Result<Option<PrimaryRoute>> {
    #[derive(Deserialize)]
    struct RequestFields {
        method: String,
        uri: String,
        #[serde(default, rename = "_session_probe")]
        probe: bool,
    }
    let request: RequestFields = decode_document(document, segments)?;
    if request.probe {
        return Ok(None);
    }
    let uri: http::Uri = request.uri.parse().context("invalid primary URI")?;
    Ok(Some(PrimaryRoute {
        method: request.method,
        path: uri.path().to_owned(),
    }))
}
