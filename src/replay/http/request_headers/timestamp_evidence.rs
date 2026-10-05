//! Verify matched-header clock witnesses against immutable source exchanges.
use super::*;
use crate::replay::policy::HttpHeaderTimestampSelector;
use anyhow::ensure;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

pub(crate) fn verify(
    source: &Path,
    report_path: &Path,
    selector: &HttpHeaderTimestampSelector,
) -> Result<Value> {
    let bytes = fs::read(report_path)?;
    let report: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        report["finalized"] == true,
        "HTTP header timestamp evidence requires finalized Replay"
    );
    let events = report["http_request_header_mismatches"]
        .as_array()
        .context("HTTP header timestamp evidence is unavailable; run fresh Replay")?;
    let mut fingerprints = BTreeMap::new();
    let mut matched = 0;
    for event in events.iter().filter(|event| {
        selector.matches(
            event["target"]["host"].as_str().unwrap_or_default(),
            event["target"]["port"]
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or_default(),
            event["method"].as_str().unwrap_or_default(),
            event["uri"].as_str().unwrap_or_default(),
        ) && event["header"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(&selector.header))
    }) {
        ensure!(
            event["kind"] == "header_value_mismatch"
                && event["expected"]["protected"] == false
                && event["actual"]["protected"] == false,
            "HTTP header rule requires an evaluable value difference, preserving presence and multiplicity"
        );
        let expected: Vec<String> = serde_json::from_value(event["expected"]["values"].clone())?;
        let actual: Vec<String> = serde_json::from_value(event["actual"]["values"].clone())?;
        let source_time = serde_json::from_value(event["source_request_started_at"].clone())?;
        let target_time = serde_json::from_value(event["target_request_started_at"].clone())?;
        timestamp::validate(
            selector.format,
            Some(&expected),
            Some(&actual),
            crate::replay::assertion::RequestTimes {
                source: source_time,
                target: target_time,
            },
        )
        .map_err(anyhow::Error::msg)?;
        let fingerprint = event["recorded_request_fingerprint"]
            .as_str()
            .context("HTTP header source identity is unavailable; run fresh Replay")?
            .to_string();
        ensure!(
            fingerprints
                .insert(fingerprint, source_time)
                .is_none_or(|previous| previous == source_time),
            "HTTP header clock witnesses conflict for the same source exchange"
        );
        matched += 1;
    }
    ensure!(
        matched > 0,
        "no verified HTTP timestamp header difference for this selector"
    );
    let (root, mut files) = super::super::recording::files(source)?;
    let global = root.join("global-dependencies.jsonl");
    if global.is_file() {
        ensure!(
            !fs::symlink_metadata(&global)?.file_type().is_symlink(),
            "HTTP header rules refuse linked Global evidence"
        );
        files.push(global);
    }
    let mut verified = BTreeMap::new();
    let mut records = Vec::new();
    for file in files {
        super::super::recording::visit(&file, |line, record| {
            let identity = identity_from_record(&record)?;
            if !selector.matches(
                &identity.target.host,
                identity.target.port,
                &record.method,
                &uri_path_only(&record.uri),
            ) {
                return Ok(());
            }
            let headers = normalized(&record.request_headers);
            let expected = headers.get(&selector.header.to_ascii_lowercase());
            let reference = time_reference::source(&record)
                .context("HTTP header source request-time evidence is missing or invalid")?;
            timestamp::validate(
                selector.format,
                expected.map(Vec::as_slice),
                expected.map(Vec::as_slice),
                crate::replay::assertion::RequestTimes {
                    source: Some(reference),
                    target: Some(reference),
                },
            )
            .map_err(anyhow::Error::msg)?;
            ensure!(
                record.error.is_none() && record.response_status.is_some(),
                "HTTP header source exchange is not replayable"
            );
            let fingerprint = timestamp::recorded_fingerprint(&record);
            if let Some(witness) = fingerprints.get(&fingerprint) {
                ensure!(
                    *witness == Some(reference),
                    "HTTP header clock witness does not match its source exchange"
                );
                verified.insert(fingerprint.clone(), Some(reference));
                records.push(serde_json::json!({"path": file.strip_prefix(&root)?, "line":line, "fingerprint":fingerprint}));
            }
            Ok(())
        })?;
    }
    ensure!(
        verified == fingerprints,
        "HTTP header timestamp source evidence changed or is missing"
    );
    Ok(
        serde_json::json!({"matched_differences":matched, "records":records,
        "evidence_revision":format!("{:x}", Sha256::digest(bytes)), "tolerance_seconds":5}),
    )
}
