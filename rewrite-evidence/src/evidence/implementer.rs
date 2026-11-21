//! Compact, attempt-scoped evidence shown by the ordinary implementer CLI.
use super::*;

pub struct MethodEvidence {
    pub attempt: Value,
    pub failures: Vec<Value>,
}

pub fn method(root: &Path, state: &RewriteState, issue: &RewriteIssue) -> MethodEvidence {
    let api = &state.api;
    let mut attempt = json!({"api":api, "attempt":issue.attempt, "issue_id":issue.id});
    let mut failures = Vec::new();
    if issue.kind == RewriteIssueKind::TargetQuality {
        failures.push(json!({"api":api,"kind":"target_quality","reason":issue.summary}));
        return MethodEvidence { attempt, failures };
    }
    let execution = e2e_context(root, state).and_then(|context| {
        crate::e2e_run::query_implementer_execution(context, group_id(state)?, issue.attempt)
    });
    match execution {
        Ok(execution) => {
            for key in ["status", "counts"] {
                if let Some(value) = execution.get(key).filter(|value| !value.is_null()) {
                    attempt[if key == "counts" { "cases" } else { key }] = value.clone();
                }
            }
            retain_omissions(&mut attempt, &execution);
            let artifacts = &execution["case_artifacts"];
            failures.extend(
                rows(&execution["dependency_failures"])
                    .map(|group| dependency(root, api, group, artifacts)),
            );
            failures.extend(
                rows(&execution["response_failures"]).map(|group| response(api, group, artifacts)),
            );
            if issue.kind == RewriteIssueKind::TargetRuntime
                || execution["status"] == "interrupted" && execution["replay_finalized"] == false
            {
                failures.push(runtime_failure(api, issue, &execution));
            }
            let reports = relevant_reports(&failures, &execution["reports"]);
            if !reports.is_empty() {
                attempt["reports"] = json!(reports);
            }
        }
        Err(error) => {
            attempt["evidence_unavailable"] = bounded_text(&error.to_string(), 512).into();
        }
    }
    if failures.is_empty() {
        failures.push(issue_failure(api, issue));
    }
    MethodEvidence { attempt, failures }
}

fn rows(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten()
}

fn relevant_reports(failures: &[Value], reports: &Value) -> BTreeMap<String, Value> {
    let mut paths = BTreeMap::new();
    let mut include = |keys: &[&str]| {
        for key in keys {
            if let Some(path) = reports.get(*key) {
                paths.insert((*key).into(), path.clone());
            }
        }
    };
    if failures.iter().any(|failure| {
        failure["kind"]
            .as_str()
            .is_some_and(|kind| kind.starts_with("dependency_"))
    }) {
        include(&["dependency_evidence"]);
    }
    if failures.iter().any(|failure| {
        matches!(
            failure["kind"].as_str(),
            Some("target_runtime" | "replay_failure")
        )
    }) {
        include(&[
            "target_stderr",
            "target_state",
            "replay_stderr",
            "replay_stdout",
        ]);
    }
    paths
}

fn retain_omissions(attempt: &mut Value, execution: &Value) {
    for (key, summary) in [
        ("dependencies", "dependency_failures_summary"),
        ("responses", "response_failures_summary"),
    ] {
        if let Some(summary) = execution[summary].as_object()
            && summary.iter().any(|(key, value)| {
                key.starts_with("omitted") && value.as_u64().is_some_and(|n| n > 0)
            })
        {
            attempt["coverage"][key] = json!(summary);
        }
    }
}

fn runtime_failure(api: &str, issue: &RewriteIssue, execution: &Value) -> Value {
    let kind = if issue.kind == RewriteIssueKind::TargetRuntime {
        "target_runtime"
    } else {
        "replay_failure"
    };
    let reason = rows(&execution["lifecycle_errors"])
        .filter_map(Value::as_str)
        .last()
        .unwrap_or(&issue.summary);
    json!({"api":api, "kind":kind, "reason":bounded_text(reason, 512)})
}

fn issue_failure(api: &str, issue: &RewriteIssue) -> Value {
    let kind = match issue.kind {
        RewriteIssueKind::Response => "response_difference",
        RewriteIssueKind::Dependency => "dependency_evidence_unavailable",
        RewriteIssueKind::Replay => "replay_failure",
        RewriteIssueKind::TargetRuntime => "target_runtime",
        RewriteIssueKind::TargetQuality => "target_quality",
    };
    let mut failure = json!({"api":api, "kind":kind, "reason":bounded_text(&issue.summary, 512)});
    if let Some(representative) = &issue.representative
        && issue.kind == RewriteIssueKind::Response
    {
        failure["representative"] = json!({"case_id":representative.case_id});
        failure["location"] = representative.pointer.as_str().into();
        failure["expected"] = response_value(&json!(representative.expected));
        failure["received"] = response_value(&json!(representative.actual));
    }
    failure
}

fn representative(case: &Value, artifacts: &Value) -> Value {
    let case_id = case.as_str().unwrap_or_default();
    let artifact = &artifacts[case_id];
    let mut representative = json!({"case_id":artifact.get("case_id").unwrap_or(case)});
    for key in ["case_dir", "request_path"] {
        copy_field(&mut representative, key, artifact, key);
    }
    representative
}

fn response(api: &str, group: &Value, artifacts: &Value) -> Value {
    let mut sample = representative(&group["case_id"], artifacts);
    let artifact = &artifacts[group["case_id"].as_str().unwrap_or_default()];
    for key in [
        "assertion_report_path",
        "expected_response_path",
        "received_response_path",
    ] {
        copy_field(&mut sample, key, artifact, key);
    }
    let location = group.get("pointer_pattern").unwrap_or(&group["pointer"]);
    if location != &group["pointer"] {
        copy_field(&mut sample, "location", group, "pointer");
    }
    let mut failure = json!({
        "api":api,"kind":"response_difference","difference_kind":group["difference_kind"],
        "location":location,"expected":response_value(&group["expected"]),
        "received":response_value(&group["received"]),
        "case_count":group["affected_cases"],"occurrences":group["occurrences"],
        "representative":sample
    });
    cases(&mut failure, group, artifacts);
    failure
}

fn response_value(observation: &Value) -> Value {
    let mut summary = json!({"presence":observation["presence"]});
    if let Some(value) = observation.get("value") {
        match value {
            Value::Array(items) => {
                summary["type"] = "array".into();
                summary["length"] = items.len().into();
            }
            Value::Object(fields) => {
                summary["type"] = "object".into();
                summary["length"] = fields.len().into();
            }
            Value::String(text) if text.len() > 256 => {
                summary["type"] = "string".into();
                summary["bytes"] = text.len().into();
            }
            _ => summary["value"] = value.clone(),
        }
    }
    summary
}

fn dependency(root: &Path, api: &str, group: &Value, artifacts: &Value) -> Value {
    let item = &group["representative"];
    let event = item.get("event").unwrap_or(item);
    let mismatch = &event["command_mismatch"];
    let unconsumed = matches!(
        group["kind"].as_str(),
        Some("case_no_progress" | "dependency_unconsumed")
    );
    let kind = if unconsumed {
        "dependency_unconsumed"
    } else if mismatch["expected"].is_string() && mismatch["expected"] == mismatch["received"] {
        "replay_failure"
    } else {
        "dependency_mismatch"
    };
    let reason = group["reason"]
        .as_str()
        .filter(|reason| !reason.is_empty())
        .unwrap_or(if unconsumed {
            "Recorded Case dependency was not consumed"
        } else {
            "Replay rejected the dependency request or delivery"
        });
    let mut failure = json!({
        "api":api,"kind":kind,"reason":bounded_text(reason, 512),
        "case_count":group["affected_cases"],"occurrences":group["occurrences"]
    });
    for key in ["protocol", "command"] {
        copy_field(&mut failure, key, group, key);
    }
    cases(&mut failure, group, artifacts);
    let mut sample = representative(&group["case_id"], artifacts);
    copy_field(
        &mut sample,
        "dependency_scope_path",
        &artifacts[group["case_id"].as_str().unwrap_or_default()],
        "dependency_scope_path",
    );
    if sample["dependency_scope_path"].is_string()
        && let Some(case_dir) = sample["case_dir"].as_str()
        && let Ok(case_dir) = crate::case_dependencies::resolve_case_dir(root, Path::new(case_dir))
    {
        sample["case_dependency_query"] =
            json!(crate::case_dependencies::summary_command(root, &case_dir));
    }
    copy_field(
        &mut sample,
        "observed_http_status",
        group,
        "observed_primary_status",
    );
    copy_field(&mut sample, "endpoint", event, "target");
    let mut source = json!({});
    let mut target = json!({});
    copy_field(&mut target, "event_index", event, "target_event_index");
    copy_field(
        &mut target,
        "observation_id",
        event,
        "target_observation_id",
    );
    if let Some(received) = mismatch.get("received") {
        failure["expected"] = mismatch["expected"].clone();
        failure["received"] = received.clone();
        copy_field(
            &mut source,
            "dependency_sequence",
            mismatch,
            "source_dependency_sequence",
        );
        copy_field(&mut source, "reference", mismatch, "source_reference");
        copy_field(&mut source, "exchange_id", mismatch, "source_exchange_id");
    }
    let mut candidates = rows(&event["candidate_comparisons"]);
    if let Some(candidate) = candidates.next()
        && candidates.next().is_none()
        && event["candidate_comparisons_omitted"]
            .as_u64()
            .unwrap_or_default()
            == 0
    {
        for (key, field) in [
            ("reference", "source_reference"),
            ("exchange_id", "source_exchange_id"),
            ("case_id", "source_case_id"),
        ] {
            copy_field(&mut source, key, candidate, field);
        }
        if let Some(difference) = rows(&candidate["differences"]).next() {
            sample["difference"] = difference.clone();
            let total = candidate["differences"].as_array().map_or(0, Vec::len) as u64
                + candidate["differences_omitted"]
                    .as_u64()
                    .unwrap_or_default();
            if total > 1 {
                sample["difference_count"] = total.into();
            }
        }
        let hints = rule_hints(candidate);
        if !hints.is_empty() {
            failure["hints"] = json!(hints);
        }
    }
    if let Some(waiting) = item.get("waiting").filter(|_| unconsumed) {
        copy_field(&mut source, "references", waiting, "references");
        copy_field(
            &mut source,
            "pending_count",
            waiting,
            "pending_source_dependencies",
        );
    }
    if unconsumed {
        copy_field(&mut source, "reference", item, "source_reference");
        copy_field(&mut source, "signature", item, "source_signature");
    }
    if source.as_object().is_some_and(|fields| !fields.is_empty()) {
        sample["source"] = source;
    }
    if target.as_object().is_some_and(|fields| !fields.is_empty()) {
        sample["target"] = target;
    }
    failure["representative"] = sample;
    failure
}

fn cases(failure: &mut Value, group: &Value, artifacts: &Value) {
    let cases = rows(&group["cases"])
        .map(|id| {
            artifacts[id.as_str().unwrap_or_default()]
                .get("case_id")
                .unwrap_or(id)
        })
        .collect::<Vec<_>>();
    if !cases.is_empty() {
        failure["cases"] = json!(cases);
    }
    if group["omitted_cases"].as_u64().is_some_and(|n| n > 0) {
        failure["omitted_cases"] = group["omitted_cases"].clone();
    }
}

fn rule_hints(candidate: &Value) -> Vec<Value> {
    let registered = rows(&candidate["policy_findings"])
        .filter(|finding| finding["policy"].is_string() && !finding["proposal"].is_null())
        .take(3)
        .map(|finding| {
            let mut hint = json!({"kind":"rule_candidate","rule":finding["policy"]});
            for (key, field) in [
                ("location", "native_location"),
                ("value_path", "source_path"),
                ("hint", "hint"),
                ("requirements", "requirements"),
            ] {
                copy_field(&mut hint, key, finding, field);
            }
            hint
        })
        .collect::<Vec<_>>();
    if !registered.is_empty() {
        return registered;
    }
    // Strict matching already verified the complete request shape before this
    // comparison. A changed value still needs independent Source provenance.
    let differences = &candidate["differences"];
    let difference = &differences[0];
    if differences.as_array().is_some_and(|items| items.len() == 1)
        && candidate["differences_omitted"] == 0
        && difference["reason"] == "unselected native value changed"
        && difference["pointer"]
            .as_str()
            .is_some_and(|pointer| pointer.starts_with('/'))
        && crate::value_extensions::policies()
            .descriptors()
            .any(|policy| policy.id == "identity")
    {
        return vec![json!({
            "kind":"investigate_rule",
            "rule":"identity",
            "location":difference["pointer"],
            "hint":"If Source generates this value, consider an identity rule for this field.",
            "requirements":["Source proof of value generation and reuse"]
        })];
    }
    Vec::new()
}

fn copy_field(output: &mut Value, key: &str, source: &Value, field: &str) {
    if let Some(value) = source.get(field).filter(|value| !value.is_null()) {
        output[key] = value.clone();
    }
}

fn bounded_text(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_evidence_omits_unscoped_files() {
        let failures = [json!({"kind":"dependency_mismatch"})];
        let reports = json!({
            "dependency_evidence":"/reports/replay-report-dependency-evidence.json",
            "replay":"/reports/replay-report.json",
            "source_case_dependencies":"/recording/dependencies.tsv"
        });
        let paths = relevant_reports(&failures, &reports);
        assert!(!paths.contains_key("replay"));
        assert_eq!(paths["dependency_evidence"], reports["dependency_evidence"]);
        assert!(!paths.contains_key("source_case_dependencies"));
    }

    #[test]
    fn dependency_evidence_projects_precise_commands_and_case_path() {
        let root = tempfile::tempdir().unwrap();
        let case_dir = root
            .path()
            .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
            .join("recordings/example/apis/pet/case-7");
        std::fs::create_dir_all(&case_dir).unwrap();
        let scope = case_dir.join("dependency-scope.json");
        let artifacts = json!({"internal-case":{"case_id":"case-7","case_dir":case_dir,
            "request_path":case_dir.join("request.json"),"dependency_scope_path":scope}});
        let group = json!({"kind":"native_request_or_delivery_failed","case_id":"internal-case",
        "affected_cases":1,"occurrences":1,"cases":["internal-case"],"protocol":"mysql",
        "reason":"MySQL command mismatch: expected COM_QUERY, received COM_STMT_PREPARE",
        "representative":{"event":{"target_observation_id":"seen-prepare","command_mismatch":{
            "expected":"COM_QUERY","received":"COM_STMT_PREPARE","source_dependency_sequence":42
        }}}});
        let failure = dependency(root.path(), "GET /api/pet", &group, &artifacts);
        assert_eq!(failure["expected"], "COM_QUERY");
        assert_eq!(failure["received"], "COM_STMT_PREPARE");
        assert_eq!(failure["cases"], json!(["case-7"]));
        assert_eq!(failure["representative"]["case_dir"], json!(case_dir));
        assert_eq!(
            failure["representative"]["dependency_scope_path"],
            json!(scope)
        );
        assert_eq!(
            failure["representative"]["case_dependency_query"],
            json!(crate::case_dependencies::summary_command(
                root.path(),
                &case_dir
            ))
        );
        assert_eq!(
            failure["representative"]["source"]["dependency_sequence"],
            42
        );
        assert_eq!(
            failure["representative"]["target"]["observation_id"],
            "seen-prepare"
        );
        assert!(failure.get("hints").is_none());
    }

    #[test]
    fn command_and_rule_projections_use_protocol_independent_fields() {
        let group = json!({"kind":"unmatched","case_id":"case-2","affected_cases":1,"occurrences":1,
            "protocol":"custom-rpc","reason":"value changed","representative":{"event":{
                "candidate_comparisons":[{"differences":[{"pointer":"/inputs/0","reason":"unselected native value changed"}],
                    "differences_omitted":0,"policy_findings":[{"policy":"time","native_location":"/inputs/0",
                        "source_path":"","hint":"Check Source clock","requirements":["source clock"],
                        "proposal":{"private_draft":true}}]}]}}});
        let failure = dependency(Path::new("/target"), "MOTAN example", &group, &json!({}));
        assert_eq!(failure["protocol"], "custom-rpc");
        assert_eq!(
            failure["representative"]["difference"]["pointer"],
            "/inputs/0"
        );
        assert_eq!(failure["hints"][0]["rule"], "time");
        assert_eq!(failure["hints"][0]["requirements"], json!(["source clock"]));
        assert!(failure["hints"][0].get("proposal").is_none());
    }

    #[test]
    fn identity_hint_requires_a_single_complete_value_difference() {
        let mut candidate = json!({
            "differences":[{"pointer":"/literals/0","reason":"unselected native value changed"}],
            "differences_omitted":0
        });
        assert_eq!(rule_hints(&candidate)[0]["kind"], "investigate_rule");
        candidate["differences_omitted"] = 1.into();
        assert!(rule_hints(&candidate).is_empty());
        candidate["differences_omitted"] = 0.into();
        candidate["differences"][0]["reason"] = "native message structure changed".into();
        assert!(rule_hints(&candidate).is_empty());
    }

    #[test]
    fn response_groups_keep_a_path_sample_and_only_inline_small_scalars() {
        let group = json!({"case_id":"case-1","pointer":"/items/5","pointer_pattern":"/items/*",
            "expected":{"presence":"present","value":{"big":"x".repeat(1024)}},
            "received":{"presence":"present","value":null}});
        let failure = response("GET /api", &group, &json!({}));
        assert_eq!(failure["location"], "/items/*");
        assert_eq!(failure["representative"]["location"], "/items/5");
        assert_eq!(
            failure["expected"],
            json!({"presence":"present","type":"object","length":1})
        );
        assert_eq!(
            failure["received"],
            json!({"presence":"present","value":null})
        );
        assert_eq!(
            response_value(&json!({"presence":"missing"})),
            json!({"presence":"missing"})
        );
    }
}
