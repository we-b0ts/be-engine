use crate::source_diff::{AddedLine, AddedRustLines, changed_rust_lines, is_production_rust_path};
use std::path::Path;

use anyhow::Result;

pub const GATE_NAME: &str = "replay-isolation";
pub const GATE_VERSION: &str = "replay-isolation-v7";

const MAX_REPORTED_VIOLATIONS: usize = 64;
pub use traffic_rewrite_model::rewrite::target_replay_isolation::ReplayIsolationReport;

pub use traffic_rewrite_model::rewrite::target_replay_isolation::ReplayIsolationStatus;

pub use traffic_rewrite_model::rewrite::target_replay_isolation::ReplayIsolationViolation;

#[derive(Clone, Copy)]
struct ForbiddenMarker {
    rule: &'static str,
    marker: &'static str,
    reason: &'static str,
    required_change: &'static str,
}

const ALL_RUST_FORBIDDEN_MARKERS: &[ForbiddenMarker] = &[ForbiddenMarker {
    rule: "replay_hostname",
    marker: ".trp.test",
    reason: "code depends on a replay-only synthetic hostname",
    required_change: "obtain the dependency address through genuine runtime configuration or source-compatible discovery",
}];

const PRODUCTION_FORBIDDEN_MARKERS: &[ForbiddenMarker] = &[
    ForbiddenMarker {
        rule: "traffic_e2e_environment",
        marker: "traffic_e2e_",
        reason: "code depends on a traffic-e2e-owned environment variable",
        required_change: "manage the application-owned value through backend-rewrite startup env",
    },
    ForbiddenMarker {
        rule: "fake_ip_range",
        marker: "198.18.",
        reason: "code depends on the replay fake-IP range",
        required_change: "remove the replay address and use the dependency address supplied by the real runtime contract",
    },
    ForbiddenMarker {
        rule: "fake_ip_range",
        marker: "198.19.",
        reason: "code depends on the replay fake-IP range",
        required_change: "remove the replay address and use the dependency address supplied by the real runtime contract",
    },
    ForbiddenMarker {
        rule: "local_runtime_path",
        marker: ".traffic-e2e/local",
        reason: "code reads traffic-e2e private runtime state",
        required_change: "remove the private runtime-state dependency and use an application-owned input contract",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "expected-response.json",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "expected-response-after.json",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "dependencies.jsonl",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "dependencies-debug.jsonl",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "assertions.json",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "fake_dns_registry.json",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "progress.yaml",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "replay-progress.yaml",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
];

pub fn inspect_at_base(target_root: &Path, base: &str) -> Result<ReplayIsolationReport> {
    Ok(inspect_added(changed_rust_lines(target_root, base)?))
}

fn inspect_added(added: AddedRustLines) -> ReplayIsolationReport {
    let mut violations = Vec::new();

    for added_line in &added.lines {
        let lower = added_line.text.to_ascii_lowercase();
        for marker in ALL_RUST_FORBIDDEN_MARKERS {
            for byte_offset in marker_offsets(&lower, marker.marker) {
                violations.push(violation(added_line, marker, byte_offset));
            }
        }
        if is_production_rust_path(&added_line.file) {
            for marker in PRODUCTION_FORBIDDEN_MARKERS {
                for byte_offset in marker_offsets(&lower, marker.marker) {
                    violations.push(violation(added_line, marker, byte_offset));
                }
            }
        }
    }

    violations.sort();
    let omitted_violations = violations.len().saturating_sub(MAX_REPORTED_VIOLATIONS);
    violations.truncate(MAX_REPORTED_VIOLATIONS);
    let status = if violations.is_empty() && omitted_violations == 0 {
        ReplayIsolationStatus::Passed
    } else {
        ReplayIsolationStatus::Failed
    };
    ReplayIsolationReport {
        schema_version: 2,
        gate: GATE_NAME.to_string(),
        status,
        scanned_files: added.scanned_files,
        scanned_added_lines: added.lines.len(),
        violations,
        omitted_violations,
    }
}

fn violation(
    added_line: &AddedLine,
    marker: &ForbiddenMarker,
    byte_offset: usize,
) -> ReplayIsolationViolation {
    ReplayIsolationViolation {
        file: added_line.file.clone(),
        line: added_line.line,
        column: column_at(&added_line.text, byte_offset),
        rule: marker.rule.to_string(),
        matched: marker.marker.to_string(),
        reason: marker.reason.to_string(),
        required_change: marker.required_change.to_string(),
    }
}

fn column_at(value: &str, byte_offset: usize) -> usize {
    value[..byte_offset].chars().count() + 1
}

fn marker_offsets(value: &str, marker: &str) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut searched = 0;
    while let Some(relative) = value[searched..].find(marker) {
        let offset = searched + relative;
        offsets.push(offset);
        searched = offset + marker.len();
    }
    offsets
}

#[cfg(test)]
#[path = "target_replay_isolation_tests.rs"]
mod tests;
