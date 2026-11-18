//! A persisted receipt is evidence only when the original session agrees.
use super::*;

use traffic_replay::report::evidence::{SessionEvidence, array, empty, number};

pub fn validate_completed_receipt_with(
    report: &Value,
    native: &dyn SessionEvidence,
) -> Result<BatchReconciliation> {
    let receipt: BatchReconciliation =
        serde_json::from_value(report["batch_reconciliation"].clone())
            .context("actual session has no current batch reconciliation receipt")?;
    ensure!(
        report["version"] == 7 && receipt.schema == "dependency-reconciliation/v3",
        "unsupported actual Replay or batch receipt version"
    );
    ensure!(
        !receipt.session_id.is_empty()
            && report["session_id"].as_str() == Some(&receipt.session_id),
        "batch receipt belongs to a different actual session"
    );
    ensure!(
        report["finalized"] == true
            && report["complete"] == true
            && report["finalized_at"].is_string()
            && report["active_case_id"].is_null()
            && receipt.execution_complete,
        "batch session is not actually finalized and complete"
    );
    let mut cases = BTreeSet::new();
    for case in array(report, "cases")? {
        let id = case["case_id"]
            .as_str()
            .context("actual Case identity absent")?;
        ensure!(
            case["status"] == "ended" && cases.insert(id.to_owned()),
            "actual full session contains an unfinished or repeated Case"
        );
    }
    let selected = array(report, "selected_case_ids")?
        .iter()
        .map(|id| {
            id.as_str()
                .map(ToOwned::to_owned)
                .context("selected Case identity absent")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        selected.len() == cases.len()
            && selected.into_iter().collect::<BTreeSet<_>>() == cases
            && !cases.is_empty()
            && cases == receipt.required_cases
            && cases == receipt.selected_cases
            && receipt.complete_source_scope,
        "batch receipt is not one complete Source scope"
    );
    ensure!(
        receipt.source_capture_complete
            && receipt.source_inventory.unattributed_dependencies == 0
            && receipt
                .source_inventory
                .unsupported_by_scope
                .values()
                .all(|kinds| kinds.values().all(|n| *n == 0))
            && receipt.source_inventory.by_owner_kind.values().sum::<u64>()
                == receipt.source_inventory.total_mandatory,
        "Source inventory remains incomplete, unattributed, or unsupported"
    );
    ensure!(
        report["dependency_attribution_snapshot"]
            == serde_json::to_value(&receipt.dependency_attribution_snapshot)?,
        "batch receipt has a different frozen attribution snapshot"
    );
    empty(report, &["unrecorded_targets"])?;
    for optional in ["dependency_pre_matches", "case_execution_failures"] {
        ensure!(
            report
                .get(optional)
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
            "actual Replay still has {optional} obligations"
        );
    }
    ensure!(
        report["dependency_hypothesis_coverage_error"].is_null()
            && report["target_observation_coverage_error"].is_null(),
        "hypothesis or independent Target evidence coverage failed"
    );
    if let Some(journal) = report
        .get("dependency_hypothesis_journal")
        .filter(|v| v.is_object())
    {
        ensure!(
            journal["complete"] == true
                && journal["error"].is_null()
                && number(journal, "enqueued")? == number(journal, "durable")?,
            "hypothesis evidence has not become fully durable"
        );
    }
    if let Some(witnesses) = report.get("policy_witnesses").filter(|v| v.is_object()) {
        ensure!(
            witnesses["complete"] == true && number(witnesses, "omitted")? == 0,
            "actual Target evidence coverage is incomplete"
        );
    }
    let mut unused = native.validate_session(report)?;
    let shutdown = receipt
        .source_inventory
        .by_owner_kind
        .get("shutdown")
        .copied()
        .unwrap_or(0);
    if shutdown > 0 {
        unused.insert("shutdown".into(), shutdown.try_into().unwrap_or(usize::MAX));
    }
    if let Some(protocols) = report.get("dependency_protocols") {
        let protocols = protocols
            .as_object()
            .context("registered protocol reports are not an object")?;
        for (protocol, evidence) in protocols {
            ensure!(
                !protocol.is_empty() && evidence.is_object(),
                "registered protocol report has no identity or evidence"
            );
            empty(evidence, &["unmatched", "unused_case", "unused_global"])?;
            ensure!(
                number(evidence, "unmatched_count")? == 0,
                "registered protocol still has unmatched requests"
            );
            let count = usize::try_from(number(evidence, "unused_global_count")?)?;
            let total = unused.entry(protocol.clone()).or_default();
            *total = total
                .checked_add(count)
                .context("run dependency count overflow")?;
        }
    }
    empty(&report["connect_failures"], &["unused_case", "failed_case"])?;
    let startup = &report["startup_phase"];
    ensure!(
        matches!(
            startup["status"].as_str(),
            Some("verified" | "not_required")
        ) && startup["unstarted_business_dependencies"]
            .as_object()
            .is_some_and(|counts| counts.values().all(|v| v.as_u64() == Some(0))),
        "restart initialization phase did not complete"
    );
    if report["replay_policy"].is_object() {
        empty(
            &report["replay_policy"],
            &["unused_applicable_dependency_rule_ids"],
        )?;
    }
    ensure!(
        unused.values().all(|n| *n == 0)
            && receipt.unused_run_dependencies.values().all(|n| *n == 0)
            && receipt.actual_unmatched_or_unsafe == 0
            && !receipt.provisional_hypotheses_used
            && receipt.startup_phase_complete
            && receipt.dependency_inventory_verified,
        "actual batch still has dependency obligations"
    );
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::replay::report::validation::validate_completed_receipt;

    fn completed() -> Value {
        let cases = BTreeSet::from(["case-a".to_owned(), "case-b".to_owned()]);
        let receipt = BatchReconciliation {
            schema: "dependency-reconciliation/v3".into(),
            session_id: "actual-session".into(),
            source_inventory_id: "source-manifest".into(),
            recording_run_id: "source-run".into(),
            recording_run_epoch: Uuid::nil(),
            process_epochs: vec![Uuid::nil()],
            dependency_attribution_snapshot: Some("proof-snapshot".into()),
            complete_source_scope: true,
            source_capture_complete: true,
            execution_complete: true,
            required_cases: cases.clone(),
            selected_cases: cases,
            source_inventory: SemanticInventory::default(),
            unused_run_dependencies: ["mysql", "http", "redis", "memcached", "motan", "kafka"]
                .into_iter()
                .map(|p| (p.into(), 0))
                .collect(),
            actual_unmatched_or_unsafe: 0,
            provisional_hypotheses_used: false,
            startup_phase_complete: true,
            dependency_inventory_verified: true,
        };
        let mut report = serde_json::json!({"version":7,"session_id":"actual-session", "complete":true,"finalized":true,
            "finalized_at":"2026-10-31T00:00:00Z", "active_case_id":null,
            "cases":[{"case_id":"case-a","status":"ended"},{"case_id":"case-b","status":"ended"}],
            "selected_case_ids":["case-a","case-b"], "dependency_attribution_snapshot":"proof-snapshot",
            "unused_global_exchange_count":0,"unused_global_http_exchange_count":0,
            "connect_failures":{"unused_case":[],"failed_case":[]},
            "http_ingress":{"pending":0,"omitted":0,"observations":[]},
            "startup_phase":{"status":"not_required","unstarted_business_dependencies":{}},
            "batch_reconciliation":receipt});
        for field in [
            "unmatched_queries",
            "unsupported_commands",
            "unused_case_exchanges",
            "unmatched_http_requests",
            "unsupported_http_exchanges",
            "http_request_header_mismatches",
            "unused_case_http_exchanges",
            "unrecorded_targets",
            "unused_global_exchanges",
            "unused_global_http_exchanges",
        ] {
            report[field] = serde_json::json!([]);
        }
        for protocol in ["redis", "memcached", "motan", "kafka"] {
            report[protocol] = serde_json::json!({"unmatched":[],"unsupported":[],"unsafe_events":[],"unused_case":[],"unused_global":[],"unused_global_count":0});
        }
        report
    }

    #[test]
    fn validates_one_complete_actual_session() {
        let receipt = validate_completed_receipt(&completed()).unwrap();
        assert_eq!(receipt.required_cases.len(), 2);
    }

    #[test]
    fn registered_protocol_receipts_include_actual_delivery_debt() {
        let mut report = completed();
        report["dependency_protocols"] = serde_json::json!({"custom-native":{
            "matched_count":3, "unmatched_count":0, "unmatched":[],
            "unused_case":[], "unused_global":[], "unused_global_count":0
        }});
        report["batch_reconciliation"]["unused_run_dependencies"]["custom-native"] = 0.into();
        assert!(
            validate_completed_receipt(&report)
                .unwrap()
                .dependency_inventory_verified
        );
        for (field, value) in [
            ("unused_case", serde_json::json!([{}])),
            ("unused_global", serde_json::json!([{}])),
            ("unused_global_count", serde_json::json!(1)),
            ("unmatched", serde_json::json!([{}])),
            ("unmatched_count", serde_json::json!(1)),
            ("unmatched_count", Value::Null),
        ] {
            let mut invalid = report.clone();
            invalid["dependency_protocols"]["custom-native"][field] = value;
            assert!(validate_completed_receipt(&invalid).is_err(), "{field}");
        }
    }

    #[test]
    fn registered_only_sessions_validate_without_historical_native_layouts() {
        let mut report = completed();
        let fields = report.as_object_mut().unwrap();
        for field in [
            "unmatched_queries",
            "unsupported_commands",
            "unused_case_exchanges",
            "unused_global_exchanges",
            "unused_global_exchange_count",
            "unmatched_http_requests",
            "unsupported_http_exchanges",
            "http_request_header_mismatches",
            "unused_case_http_exchanges",
            "unused_global_http_exchanges",
            "unused_global_http_exchange_count",
            "http_ingress",
            "redis",
            "memcached",
            "motan",
            "kafka",
        ] {
            fields.remove(field);
        }
        report["dependency_protocols"] = serde_json::json!({"custom-native":{
            "unmatched_count":0,"unmatched":[],"unused_case":[],
            "unused_global":[],"unused_global_count":0
        }});
        report["batch_reconciliation"]["unused_run_dependencies"] =
            serde_json::json!({"custom-native":0});
        assert!(validate_completed_receipt(&report).is_ok());
        for field in [
            "unsupported_commands",
            "unsupported_http_exchanges",
            "redis",
        ] {
            let mut incomplete = report.clone();
            incomplete[field] = serde_json::json!([]);
            assert!(validate_completed_receipt(&incomplete).is_err(), "{field}");
        }
        report["batch_reconciliation"]["unused_run_dependencies"]["custom-native"] =
            serde_json::json!(1);
        assert!(validate_completed_receipt(&report).is_err());
    }

    #[test]
    fn associated_shutdown_cannot_disappear_into_a_whole_source_pass() {
        let mut report = completed();
        report["batch_reconciliation"]["source_inventory"]["total_mandatory"] =
            serde_json::json!(1);
        report["batch_reconciliation"]["source_inventory"]["by_owner_kind"]["shutdown"] =
            serde_json::json!(1);
        // Even a relabeled optimistic receipt cannot replace real teardown I/O.
        assert!(validate_completed_receipt(&report).is_err());
    }

    #[test]
    fn independent_case_acceptance_does_not_close_the_startup_batch_obligations() {
        let mut report = completed();
        report["startup_phase"] = serde_json::json!({
            "status":"verified",
            "boundary_case_id":"case-a",
            "business_inventory":{"redis":2},
            "unstarted_business_dependencies":{"redis":2}
        });
        assert!(!crate::protocols::replay::report::evidence::report_has_case_dirty_events(&report));
        assert!(
            validate_completed_receipt(&report)
                .unwrap_err()
                .to_string()
                .contains("restart initialization phase did not complete")
        );
    }

    #[test]
    fn a_success_flag_cannot_hide_real_unfinished_or_foreign_evidence() {
        for (pointer, value) in [
            ("/session_id", serde_json::json!("another-session")),
            ("/cases/1/case_id", serde_json::json!("case-a")),
            ("/cases/1/status", serde_json::json!("pending")),
            ("/redis/unused_global_count", serde_json::json!(1)),
            ("/unmatched_queries", serde_json::json!([{"case_id":null}])),
            ("/http_ingress/pending", serde_json::json!(1)),
            (
                "/http_ingress/observations",
                serde_json::json!([{"status":"cancelled"}]),
            ),
            (
                "/startup_phase/status",
                serde_json::json!("phase_unverified"),
            ),
            (
                "/dependency_attribution_snapshot",
                serde_json::json!("old-proof"),
            ),
            (
                "/batch_reconciliation/source_inventory/unattributed_dependencies",
                serde_json::json!(1),
            ),
        ] {
            let mut report = completed();
            *report.pointer_mut(pointer).unwrap() = value;
            assert!(validate_completed_receipt(&report).is_err(), "{pointer}");
        }
    }
}
