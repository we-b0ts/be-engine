use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::super::config::{fingerprint, load_replay_policy};
use super::super::response::{
    Hessian2ValuePath, MotanBodyProtocol, MotanResponseRule, MotanUnorderedPath, ProtobufFieldPath,
    motan_response_rule_id, parse_api,
};
use super::document::{render_response_rules, replace_response_rules};
use crate::comparison_recording::{
    ComparisonVerificationClassification, ComparisonVerificationOptions,
    ComparisonVerificationOutcome, ComparisonVerificationReport, verify_comparison_recording,
};
use crate::config::edit::write_atomic;
use crate::replay::{
    ComparisonSourceMatch, Hessian2ValuePathCandidate, MotanBodyDifference,
    MotanUnorderedPathCandidate, ProtobufFieldPathCandidate, ResponseDifferenceKind,
    is_motan_hessian2_body, is_motan_protobuf_body, read_comparison_response_observation,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum BodyPath {
    Protobuf(ProtobufFieldPath),
    Hessian2(Hessian2ValuePath),
}

#[derive(Debug, Clone)]
pub struct MotanRuleFeedback {
    pub policy_path: PathBuf,
    pub api: String,
    pub protocol: MotanBodyProtocol,
    pub unordered_paths: Vec<MotanUnorderedPath>,
    pub comparison_report: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct MotanRuleReport {
    pub policy: PathBuf,
    pub policy_fingerprint: String,
    pub comparison_report: PathBuf,
    pub comparison_fingerprint: String,
    pub api: String,
    pub rule_id: String,
    pub protocol: MotanBodyProtocol,
    pub matching_cases: usize,
    pub selected_difference_cases: usize,
    pub discovered_unordered_paths: Vec<MotanUnorderedPathCandidate>,
    pub effective_unordered_paths: Vec<MotanUnorderedPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_comparison: Option<ComparisonVerificationOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_only: Option<bool>,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

pub struct MotanRulePlan {
    policy_path: PathBuf,
    original: String,
    updated: String,
    comparison_case_source: PathBuf,
    report: MotanRuleReport,
}

impl MotanRulePlan {
    pub fn report(&self) -> &MotanRuleReport {
        &self.report
    }

    pub fn apply(self) -> Result<MotanRuleReport> {
        let current = fs::read_to_string(&self.policy_path).with_context(|| {
            format!(
                "failed to reread replay policy {}",
                self.policy_path.display()
            )
        })?;
        ensure!(
            current == self.original,
            "replay policy changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.policy_path, self.updated.as_bytes())?;
        }
        let mut report = self.report;
        let verification = verify_comparison_recording(ComparisonVerificationOptions {
            case_source: self.comparison_case_source,
            policy: self.policy_path.clone(),
            report: report.comparison_report.clone(),
        })?;
        let matching = verification
            .cases
            .iter()
            .filter(|case| case.api == report.api)
            .collect::<Vec<_>>();
        ensure!(
            !matching.is_empty(),
            "offline Motan verification contains no cases for {}",
            report.api
        );
        let motan_reports = matching
            .iter()
            .filter_map(|case| case.response.as_ref()?.motan.as_ref())
            .collect::<Vec<_>>();
        ensure!(
            motan_reports.len() == matching.len(),
            "offline Motan verification did not produce protocol-aware body reports"
        );
        report.discovered_unordered_paths = motan_reports
            .iter()
            .flat_map(|motan| motan.unordered_path_candidates.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        report.order_only = Some(motan_reports.iter().all(|motan| motan.order_only));
        report.offline_comparison = Some(verification.outcome());
        report.policy_fingerprint = verification.policy_fingerprint;
        report.comparison_fingerprint = fingerprint(&read_regular(
            &report.comparison_report,
            "refreshed comparison report",
        )?);
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_motan_rule(feedback: MotanRuleFeedback) -> Result<MotanRulePlan> {
    let (method, _) = parse_api(&feedback.api)?;
    ensure!(
        method == "MOTAN",
        "Motan response rule API must use canonical method MOTAN"
    );
    let original = read_regular_text(&feedback.policy_path, "replay policy")?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    ensure!(
        loaded.document.version >= 2,
        "Motan response rules require replay policy version 2"
    );
    let comparison_bytes = read_regular(&feedback.comparison_report, "comparison report")?;
    let comparison: ComparisonVerificationReport =
        serde_json::from_slice(&comparison_bytes).context("invalid comparison report")?;
    ensure!(
        comparison.version == 5
            && comparison.kind == "comparison_recording_verification"
            && comparison.expected_response == "assertions_only"
            && comparison.assertion_mode == "comparison_recording",
        "Motan rule planning requires current comparison recording verification evidence"
    );
    ensure!(
        comparison.complete,
        "comparison recording verification evidence must be complete"
    );
    ensure!(
        comparison.policy_fingerprint == loaded.fingerprint,
        "comparison report replay policy fingerprint is stale"
    );

    let existing = loaded
        .document
        .response_rules
        .motan
        .get(&feedback.api)
        .cloned();
    if let Some(existing) = &existing {
        ensure!(
            existing.protocol == feedback.protocol,
            "Motan response rule already uses a different protocol"
        );
    }
    let protocol_configured = existing.is_some();
    ensure!(
        feedback
            .unordered_paths
            .iter()
            .all(|path| path.protocol() == feedback.protocol),
        "Motan rule plan contains an unordered path for a different body protocol"
    );
    ensure!(
        protocol_configured || feedback.unordered_paths.is_empty(),
        "configure the Motan body protocol before adding unordered paths; apply the protocol configuration to obtain protocol-aware comparison evidence"
    );
    let matching = comparison
        .cases
        .iter()
        .filter(|case| case.api == feedback.api)
        .collect::<Vec<_>>();
    ensure!(
        !matching.is_empty(),
        "comparison evidence contains no cases for {}",
        feedback.api
    );
    let mut selected_difference_cases = 0;
    let mut discovered = BTreeSet::new();
    let mut diagnostic_paths = BTreeSet::new();
    for case in &matching {
        ensure!(
            case.classification != ComparisonVerificationClassification::PolicyMismatch
                && case.policy_mismatch_rule_ids.is_empty(),
            "case {:?} has an unused applicable response rule",
            case.case_id
        );
        ensure!(
            case.source_change_pointers.is_empty(),
            "case {:?} has source changes and cannot authorize a Motan response rule",
            case.case_id
        );
        if case.passed {
            continue;
        }
        ensure!(
            case.classification == ComparisonVerificationClassification::CandidateDifference,
            "case {:?} is not a candidate-only response difference",
            case.case_id
        );
        let response = case
            .response
            .as_ref()
            .with_context(|| format!("case {:?} has no response assertion", case.case_id))?;
        ensure!(
            response.differences.len() == 1
                && response.differences[0].pointer == "$body"
                && response.differences[0].kind == ResponseDifferenceKind::ExactBodyMismatch,
            "case {:?} has differences other than the exact Motan body",
            case.case_id
        );
        let motan = response.motan.as_ref();
        if let Some(motan) = motan {
            ensure!(
                motan.rule_kind == "motan",
                "case {:?} has an invalid Motan body report",
                case.case_id
            );
            let protocol_reported = motan.protocol == feedback.protocol
                || (!motan.configured && motan.protocol_candidates.contains(&feedback.protocol));
            if !protocol_reported && !protocol_configured && !motan.configured {
                validate_unreported_protocol_candidate(
                    Path::new(&case.case_dir),
                    &case.case_id,
                    feedback.protocol,
                )?;
            } else {
                ensure!(
                    protocol_reported,
                    "case {:?} does not support the requested Motan protocol",
                    case.case_id
                );
            }
        } else if !protocol_configured {
            validate_unreported_protocol_candidate(
                Path::new(&case.case_dir),
                &case.case_id,
                feedback.protocol,
            )?;
        } else {
            anyhow::bail!(
                "case {:?} was not evaluated with the configured Motan protocol",
                case.case_id
            );
        }
        selected_difference_cases += 1;
        if protocol_configured {
            let motan = motan.context("configured Motan protocol report is missing")?;
            ensure!(
                motan.configured,
                "case {:?} was not evaluated with the configured Motan protocol",
                case.case_id
            );
            discovered.extend(
                motan
                    .unordered_path_candidates
                    .iter()
                    .filter_map(|candidate| body_path_from_candidate(candidate, feedback.protocol)),
            );
            diagnostic_paths.extend(
                motan.differences.iter().filter_map(|difference| {
                    body_path_from_difference(difference, feedback.protocol)
                }),
            );
        }
    }
    ensure!(
        selected_difference_cases > 0,
        "comparison evidence contains no exact Motan body difference"
    );
    let existing_fields = existing
        .as_ref()
        .into_iter()
        .flat_map(|rule| rule.unordered_paths.iter())
        .map(body_path_from_rule)
        .collect::<BTreeSet<_>>();
    let new_discovered = discovered
        .difference(&existing_fields)
        .cloned()
        .collect::<BTreeSet<_>>();
    if protocol_configured {
        let requested = feedback
            .unordered_paths
            .iter()
            .map(body_path_from_rule)
            .collect::<BTreeSet<_>>();
        ensure!(
            requested.len() == feedback.unordered_paths.len(),
            "Motan rule plan repeats an unordered body path"
        );
        ensure!(
            !requested.is_empty(),
            "the configured Motan body protocol requires at least one reviewed unordered path from current protocol-aware comparison evidence"
        );
        ensure!(
            requested.is_disjoint(&existing_fields),
            "Motan rule plan repeats a body path already present in the rule"
        );
        ensure!(
            new_discovered.is_subset(&requested),
            "Motan rule plan must include every newly discovered unordered body path"
        );
        ensure!(
            requested.is_subset(&diagnostic_paths),
            "Motan rule plan paths must be present in the protocol-aware comparison differences"
        );
    }

    let mut effective_paths = existing
        .as_ref()
        .into_iter()
        .flat_map(|rule| rule.unordered_paths.iter().cloned())
        .map(|path| (body_path_from_rule(&path), path))
        .collect::<BTreeMap<_, _>>();
    effective_paths.extend(
        feedback
            .unordered_paths
            .iter()
            .cloned()
            .map(|path| (body_path_from_rule(&path), path)),
    );
    let effective_paths = effective_paths.into_values().collect::<Vec<_>>();
    if protocol_configured {
        for case in matching.iter().filter(|case| !case.passed) {
            let case_dir = Path::new(&case.case_dir);
            let expected = read_comparison_response_observation(
                &case_dir.join("expected-response.json"),
                "source-before response",
            )?;
            let actual = read_comparison_response_observation(
                &case_dir.join("response.json"),
                "candidate response",
            )?;
            let matches_before = compare_motan_body(
                &expected.body,
                &actual.body,
                feedback.protocol,
                &effective_paths,
            )?;
            let matches_after = if !matches_before
                && comparison.source_match == ComparisonSourceMatch::BeforeOrAfter
                && case.response_after.is_some()
            {
                let after = read_comparison_response_observation(
                    &case_dir.join("expected-response-after.json"),
                    "source-after response",
                )?;
                compare_motan_body(
                    &after.body,
                    &actual.body,
                    feedback.protocol,
                    &effective_paths,
                )?
            } else {
                false
            };
            ensure!(
                matches_before || matches_after,
                "reviewed Motan unordered paths do not fully explain case {:?}",
                case.case_id
            );
        }
    }
    loaded.document.response_rules.motan.insert(
        feedback.api.clone(),
        MotanResponseRule {
            protocol: feedback.protocol,
            unordered_paths: effective_paths.clone(),
        },
    );
    let updated = replace_response_rules(&original, &loaded.document.response_rules)?;
    let changed = updated != original;
    let diff = if changed {
        format!(
            "--- {}\n+++ {}\n@@ response_rules @@\n{}",
            feedback.policy_path.display(),
            feedback.policy_path.display(),
            render_response_rules(&loaded.document.response_rules)?
                .lines()
                .map(|line| format!("+{line}\n"))
                .collect::<String>()
        )
    } else {
        String::new()
    };

    Ok(MotanRulePlan {
        policy_path: feedback.policy_path.clone(),
        original,
        updated,
        comparison_case_source: PathBuf::from(&comparison.case_source),
        report: MotanRuleReport {
            policy: feedback.policy_path,
            policy_fingerprint: loaded.fingerprint,
            comparison_report: feedback.comparison_report,
            comparison_fingerprint: fingerprint(&comparison_bytes),
            api: feedback.api.clone(),
            rule_id: motan_response_rule_id(&feedback.api),
            protocol: feedback.protocol,
            matching_cases: matching.len(),
            selected_difference_cases,
            discovered_unordered_paths: discovered
                .into_iter()
                .map(candidate_from_body_path)
                .collect(),
            effective_unordered_paths: effective_paths,
            offline_comparison: None,
            order_only: None,
            changed,
            applied: false,
            diff,
        },
    })
}

fn validate_unreported_protocol_candidate(
    case_dir: &Path,
    case_id: &str,
    protocol: MotanBodyProtocol,
) -> Result<()> {
    let expected = read_comparison_response_observation(
        &case_dir.join("expected-response.json"),
        "source-before response",
    )?;
    let actual = read_comparison_response_observation(
        &case_dir.join("response.json"),
        "candidate response",
    )?;
    match protocol {
        MotanBodyProtocol::Protobuf => {
            ensure!(
                is_motan_protobuf_body(&expected.body),
                "case {case_id:?} source-before body is not a valid protobuf simple byte-array envelope"
            );
            ensure!(
                is_motan_protobuf_body(&actual.body),
                "case {case_id:?} candidate body is not a valid protobuf simple byte-array envelope"
            );
        }
        MotanBodyProtocol::Hessian2 => {
            ensure!(
                is_motan_hessian2_body(&expected.body),
                "case {case_id:?} source-before body is not a valid Hessian2 simple byte-array envelope"
            );
            ensure!(
                is_motan_hessian2_body(&actual.body),
                "case {case_id:?} candidate body is not a valid Hessian2 simple byte-array envelope"
            );
        }
    }
    Ok(())
}

fn body_path_from_rule(path: &MotanUnorderedPath) -> BodyPath {
    match path {
        MotanUnorderedPath::Protobuf(path) => BodyPath::Protobuf(path.field_path.clone()),
        MotanUnorderedPath::Hessian2(path) => BodyPath::Hessian2(path.value_path.clone()),
    }
}

fn body_path_from_candidate(
    path: &MotanUnorderedPathCandidate,
    protocol: MotanBodyProtocol,
) -> Option<BodyPath> {
    match (path, protocol) {
        (MotanUnorderedPathCandidate::Protobuf(path), MotanBodyProtocol::Protobuf) => {
            Some(BodyPath::Protobuf(path.field_path.clone()))
        }
        (MotanUnorderedPathCandidate::Hessian2(path), MotanBodyProtocol::Hessian2) => {
            Some(BodyPath::Hessian2(path.value_path.clone()))
        }
        _ => None,
    }
}

fn body_path_from_difference(
    difference: &MotanBodyDifference,
    protocol: MotanBodyProtocol,
) -> Option<BodyPath> {
    match (difference, protocol) {
        (MotanBodyDifference::Protobuf(difference), MotanBodyProtocol::Protobuf) => {
            Some(BodyPath::Protobuf(difference.field_path.clone()))
        }
        (MotanBodyDifference::Hessian2(difference), MotanBodyProtocol::Hessian2) => {
            Some(BodyPath::Hessian2(difference.value_path.clone()))
        }
        _ => None,
    }
}

fn candidate_from_body_path(path: BodyPath) -> MotanUnorderedPathCandidate {
    match path {
        BodyPath::Protobuf(field_path) => {
            MotanUnorderedPathCandidate::Protobuf(ProtobufFieldPathCandidate::from(field_path))
        }
        BodyPath::Hessian2(value_path) => {
            MotanUnorderedPathCandidate::Hessian2(Hessian2ValuePathCandidate::from(value_path))
        }
    }
}

fn compare_motan_body(
    expected: &[u8],
    actual: &[u8],
    protocol: MotanBodyProtocol,
    unordered_paths: &[MotanUnorderedPath],
) -> Result<bool> {
    match protocol {
        MotanBodyProtocol::Protobuf => {
            let paths = unordered_paths
                .iter()
                .map(|path| match path {
                    MotanUnorderedPath::Protobuf(path) => Ok(path.clone()),
                    MotanUnorderedPath::Hessian2(_) => {
                        anyhow::bail!("protobuf rule contains a Hessian2 unordered path")
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            crate::replay::assertion::protobuf::compare_motan_protobuf(expected, actual, &paths)
        }
        MotanBodyProtocol::Hessian2 => {
            let paths = unordered_paths
                .iter()
                .map(|path| match path {
                    MotanUnorderedPath::Hessian2(path) => Ok(path.clone()),
                    MotanUnorderedPath::Protobuf(_) => {
                        anyhow::bail!("Hessian2 rule contains a protobuf unordered path")
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            crate::replay::assertion::hessian2::compare_motan_hessian2(expected, actual, &paths)
        }
    }
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink"
    );
    fs::read(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

fn read_regular_text(path: &Path, label: &str) -> Result<String> {
    String::from_utf8(read_regular(path, label)?)
        .with_context(|| format!("{label} {} is not UTF-8", path.display()))
}
