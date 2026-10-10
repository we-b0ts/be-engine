use super::*;
use crate::rewrite::model::{RewriteIssue, RewriteIssueOwner, RewritePhase};
use std::fs;
use tempfile::tempdir;

fn dependency_state() -> RewriteState {
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(RewriteIssue {
        id: "issue-dependency".to_string(),
        kind: RewriteIssueKind::Dependency,
        owner: RewriteIssueOwner::SourceInvestigation,
        summary: "dependency evidence is dirty".to_string(),
        pointer_pattern: None,
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
    });
    state.dependency_rule_plan = Some(RewriteDependencyRulePlanRecord {
        review_fingerprint: None,
        id: "dependency-plan-original".to_string(),
        issue_id: "issue-dependency".to_string(),
        evidence_id: "evidence-dirty-clusters".to_string(),
        name: "cache-warm".to_string(),
        source_evidence: "src/cache.rs:warm".to_string(),
        spec: RewriteDependencyRuleSpec::RedisScard {
            ports: vec![6379],
            keys: vec!["cache:key".to_string()],
            initial_load_timeout_ms: 60_000,
        },
        reused_existing: false,
        effective_name: None,
    });
    state
}

#[test]
fn persisted_plan_remains_applicable_after_plan_revision_bump() {
    let mut state = dependency_state();
    state.bump();

    let record = pending_plan_for_apply(&state, "dependency-plan-original").unwrap();

    assert_eq!(record.evidence_id, "evidence-dirty-clusters");
}

#[test]
fn header_timestamp_remains_request_owned_and_rechecks_persisted_evidence() {
    let mut state = dependency_state();
    let spec = RewriteDependencyRuleSpec::HttpHeaderTimestamp {
        selector: crate::HttpHeaderTimestampSelector {
            host: "storage.example.test".into(),
            port: 9100,
            method: "GET".into(),
            path: "/bucket/*".into(),
            header: "x-amz-date".into(),
            format: crate::ResponseTimestampFormat::AmzDate,
        },
    };
    state.dependency_rule_plan.as_mut().unwrap().spec = spec.clone();
    for kind in [
        RewriteIssueKind::Response,
        RewriteIssueKind::Dependency,
        RewriteIssueKind::Replay,
    ] {
        state.active_issue.as_mut().unwrap().kind = kind;
        assert!(dependency_issue(&state, &spec).is_ok());
        assert!(
            validate_plan_evidence(
                Path::new("/missing-target"),
                &state,
                "issue-dependency",
                "evidence-dirty-clusters",
                &spec
            )
            .is_err()
        );
    }
}

#[test]
fn http_unordered_remains_request_owned_and_rechecks_persisted_evidence() {
    let mut state = dependency_state();
    let spec = RewriteDependencyRuleSpec::HttpUnordered {
        selector: crate::HttpUnorderedSelector {
            host: "erp.example.test".into(),
            port: 80,
            method: "POST".into(),
            path: "/membership".into(),
            pointer: "/department_ids".into(),
        },
    };
    state.dependency_rule_plan.as_mut().unwrap().spec = spec.clone();
    for kind in [
        RewriteIssueKind::Response,
        RewriteIssueKind::Dependency,
        RewriteIssueKind::Replay,
    ] {
        state.active_issue.as_mut().unwrap().kind = kind;
        assert!(dependency_issue(&state, &spec).is_ok());
        assert!(
            validate_plan_evidence(
                Path::new("/missing-target"),
                &state,
                "issue-dependency",
                "evidence-dirty-clusters",
                &spec
            )
            .is_err()
        );
    }
}

#[test]
fn redis_unordered_remains_request_owned_and_rechecks_persisted_evidence() {
    let mut state = dependency_state();
    let spec = RewriteDependencyRuleSpec::RedisUnordered {
        selector: crate::RedisUnorderedSelector {
            host: "redis.test".into(),
            port: 6379,
            key: crate::RedisValueKeySelector::Affix {
                prefix: "erp:membership:".into(),
                suffix: String::new(),
            },
            field: crate::RedisUnorderedField::Json {
                pointer: "/ids".into(),
            },
        },
    };
    state.dependency_rule_plan.as_mut().unwrap().spec = spec.clone();
    for kind in [
        RewriteIssueKind::Response,
        RewriteIssueKind::Dependency,
        RewriteIssueKind::Replay,
    ] {
        state.active_issue.as_mut().unwrap().kind = kind;
        assert!(dependency_issue(&state, &spec).is_ok());
        assert!(
            validate_plan_evidence(
                Path::new("/missing-target"),
                &state,
                "issue-dependency",
                "evidence-dirty-clusters",
                &spec
            )
            .is_err()
        );
    }
}

#[test]
fn apply_does_not_revalidate_revision_scoped_evidence() {
    let mut state = dependency_state();
    state.bump();

    let error = apply(
        Path::new("/missing-target"),
        &mut state,
        "dependency-plan-original",
    )
    .unwrap_err();

    assert!(!state.rule_replay_pending);
    assert!(
        error
            .to_string()
            .contains("requires a finalized case source")
    );
}

#[test]
fn pending_plan_evidence_can_replace_an_incomplete_preview() {
    let mut state = dependency_state();
    state.bump();

    validate_plan_evidence(
        Path::new("/missing-target"),
        &state,
        "issue-dependency",
        "evidence-dirty-clusters",
        &state.dependency_rule_plan.as_ref().unwrap().spec,
    )
    .unwrap();
}

#[test]
fn pending_plan_evidence_cannot_cross_issue_boundaries() {
    let state = dependency_state();

    let error = validate_plan_evidence(
        Path::new("/missing-target"),
        &state,
        "issue-other",
        "evidence-dirty-clusters",
        &state.dependency_rule_plan.as_ref().unwrap().spec,
    )
    .unwrap_err();

    assert!(error.to_string().contains("evidence is stale"));
}

#[test]
fn request_owned_classification_requires_target_implementation_without_a_rule_plan() {
    let target = tempdir().unwrap();
    let mut state = dependency_state();
    let issue = state.active_issue.clone().unwrap();
    let selector = serde_json::json!({
        "protocol": "motan",
        "group": "yf-tkv-rpc",
        "interface_name": "com.weibo.api.mcq.rpc.KafkaService",
        "method_name": "sender",
    });

    let report = classify_non_process_owned(
        target.path(),
        &mut state,
        issue,
        RewriteDependencyRulePlanOptions {
            evidence_id: "evidence-dirty-clusters".to_string(),
            ownership: RewriteDependencyOwnership::RequestOwned,
            name: None,
            source_evidence: Some(
                "TrafficProcessorImpl.java:onCompletion audit sender".to_string(),
            ),
            selector: RewriteDependencyRuleSelector::Motan {
                group: "yf-tkv-rpc".to_string(),
                interface_name: "com.weibo.api.mcq.rpc.KafkaService".to_string(),
                method_name: "sender".to_string(),
            },
        },
        selector,
    )
    .unwrap();

    assert_eq!(report.ownership, RewriteDependencyOwnership::RequestOwned);
    assert!(!report.process_owned_rule_applicable);
    assert!(report.target_implementation_required);
    assert!(report.plan_id.is_none());
    assert!(state.dependency_rule_plan.is_none());
    let issue = state.active_issue.as_ref().unwrap();
    assert_eq!(issue.owner, RewriteIssueOwner::TargetCode);
    assert!(
        issue
            .summary
            .contains("implement the recorded request-owned")
    );
    assert_eq!(
        issue.possible_causes,
        vec!["request_owned_dependency_not_implemented"]
    );
}

#[test]
fn unresolved_classification_preserves_source_investigation_without_a_rule_plan() {
    let target = tempdir().unwrap();
    let mut state = dependency_state();
    let issue = state.active_issue.clone().unwrap();

    let report = classify_non_process_owned(
        target.path(),
        &mut state,
        issue,
        RewriteDependencyRulePlanOptions {
            evidence_id: "evidence-dirty-clusters".to_string(),
            ownership: RewriteDependencyOwnership::Unresolved,
            name: None,
            source_evidence: None,
            selector: RewriteDependencyRuleSelector::RedisGet {
                ports: vec![6379],
                keys: vec!["cache:key".to_string()],
                initial_load_timeout_ms: 60_000,
            },
        },
        serde_json::json!({"protocol": "redis_get", "ports": [6379]}),
    )
    .unwrap();

    assert_eq!(report.ownership, RewriteDependencyOwnership::Unresolved);
    assert!(!report.process_owned_rule_applicable);
    assert!(!report.target_implementation_required);
    assert!(state.dependency_rule_plan.is_none());
    let issue = state.active_issue.as_ref().unwrap();
    assert_eq!(issue.owner, RewriteIssueOwner::SourceInvestigation);
    assert!(issue.summary.contains("determine whether"));
}

#[test]
fn rejected_redis_snapshot_derivation_can_schedule_a_fresh_recording_fallback() {
    let target = tempdir().unwrap();
    fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
    crate::rewrite::test_support::install_project_config(
        target.path(),
        "master",
        crate::config::AppConfig::default(),
        None,
    );
    let mut state = dependency_state();
    let applied = pending_cache_snapshot_refresh(&state, "dependency-plan-original")
        .unwrap()
        .unwrap();

    schedule_cache_snapshot_refresh(target.path(), &mut state, applied).unwrap();

    assert_eq!(state.phase, RewritePhase::AwaitingRecordingRefresh);
    let refresh = state.recording_refresh.unwrap();
    assert!(refresh.applied.is_empty());
    assert_eq!(refresh.dependency_rules.len(), 1);
    assert_eq!(refresh.dependency_rules[0].rule_name, "cache-warm");
    assert!(refresh.recording_run_id.is_none());
}

#[test]
fn mysql_plan_survives_persistence_without_requesting_redis_snapshot_recording() {
    let mut state = dependency_state();
    let selector = crate::MysqlBackgroundSelector {
        target_host: "db.internal".into(),
        target_port: 3306,
        database: "app".into(),
        username: "user".into(),
        sql: "SELECT {{table}}.id AS {{table}}_id FROM {{table}} WHERE status='RUNNING'".into(),
        tables: vec!["subtasks".into()],
        table_patterns: vec!["subtasks_*".into()],
        table_series: None,
    };
    state.dependency_rule_plan.as_mut().unwrap().spec =
        spec_from_selector(RewriteDependencyRuleSelector::Mysql {
            selector: selector.clone(),
        });
    let serialized = serde_json::to_string(&state).unwrap();
    let state: RewriteState = serde_json::from_str(&serialized).unwrap();
    let record = pending_plan_for_apply(&state, "dependency-plan-original").unwrap();
    let RewriteDependencyRuleSpec::Mysql {
        selector: persisted,
    } = record.spec
    else {
        panic!("expected mysql plan");
    };
    assert_eq!(persisted, selector);
    assert!(
        pending_cache_snapshot_refresh(&state, "dependency-plan-original")
            .unwrap()
            .is_none()
    );
}

#[test]
fn mysql_time_plan_survives_response_issue_persistence_without_background_reclassification() {
    let mut state = dependency_state();
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Response;
    state.dependency_rule_plan.as_mut().unwrap().spec = RewriteDependencyRuleSpec::MysqlSqlTime {
        selector: crate::MysqlTimeSelector {
            target_host: "db.internal".into(),
            target_port: 3306,
            database: "app".into(),
            username: "user".into(),
            sql: "UPDATE keys SET stamp=? WHERE id=?".into(),
            time_values: vec![crate::MysqlTimeValueSelector {
                value_index: 0,
                json_pointer: None,
                tolerance: "5s".into(),
                offset: "0s".into(),
                format: "%Y-%m-%d %H:%M:%S%.f".into(),
                timezone: "+00:00".into(),
            }],
        },
    };
    let state: RewriteState =
        serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
    let plan = pending_plan_for_apply(&state, "dependency-plan-original").unwrap();
    assert!(matches!(
        plan.spec,
        RewriteDependencyRuleSpec::MysqlSqlTime { .. }
    ));
    assert!(
        pending_cache_snapshot_refresh(&state, "dependency-plan-original")
            .unwrap()
            .is_none()
    );
}

#[test]
fn redis_time_shift_manual_rule_rechecks_evidence_without_requiring_a_hint() {
    let mut state = dependency_state();
    let selector = serde_json::from_value(serde_json::json!({
        "host":"redis.test","port":6379,"read":{"command":"HGET","key":"token_v2","hash_field":{"numeric":true},
        "response_json":{"/timestamp":{"time":"preserve_relative","format":"unix_milliseconds"}}}
    })).unwrap();
    let spec = RewriteDependencyRuleSpec::RedisTimeShift { selector };
    state.dependency_rule_plan.as_mut().unwrap().spec = spec.clone();
    for kind in [
        RewriteIssueKind::Response,
        RewriteIssueKind::Dependency,
        RewriteIssueKind::Replay,
    ] {
        state.active_issue.as_mut().unwrap().kind = kind;
        assert!(dependency_issue(&state, &spec).is_ok());
        assert!(
            validate_plan_evidence(
                Path::new("/missing-target"),
                &state,
                "issue-dependency",
                "evidence-dirty-clusters",
                &spec
            )
            .is_err()
        );
    }
}

#[test]
fn redis_lock_retains_request_ownership_and_rechecks_current_evidence() {
    let mut state = dependency_state();
    let spec = RewriteDependencyRuleSpec::RedisLock {
        selector: crate::RedisLockSelector {
            host: "redis.test".into(),
            port: 6379,
            key: crate::RedisValueKeySelector::Exact {
                value: "lock:one".into(),
            },
        },
    };
    assert!(spec.requires_fresh_replay());
    state.dependency_rule_plan.as_mut().unwrap().spec = spec.clone();
    for kind in [
        RewriteIssueKind::Response,
        RewriteIssueKind::Dependency,
        RewriteIssueKind::Replay,
    ] {
        state.active_issue.as_mut().unwrap().kind = kind;
        assert!(dependency_issue(&state, &spec).is_ok());
        assert!(
            validate_plan_evidence(
                Path::new("/missing-target"),
                &state,
                "issue-dependency",
                "evidence-dirty-clusters",
                &spec
            )
            .is_err()
        );
    }
}

#[test]
fn redis_publish_retains_request_ownership_and_rechecks_current_evidence() {
    let mut state = dependency_state();
    let selector = crate::RedisPublishSelector {
        host: "redis.test".into(),
        port: 6379,
        channel: "events".into(),
        uuid_index: Some(0),
        uuid_field: None,
    };
    let spec =
        planner::spec_from_selector(RewriteDependencyRuleSelector::RedisPublish { selector });
    let encoded = serde_json::to_value(&spec).unwrap();
    assert_eq!(encoded["kind"], "redis_publish");
    assert_eq!(encoded["selector"]["uuid_index"], 0);
    let spec: RewriteDependencyRuleSpec = serde_json::from_value(encoded).unwrap();
    assert!(spec.requires_fresh_replay());
    state.dependency_rule_plan.as_mut().unwrap().spec = spec.clone();
    for kind in [
        RewriteIssueKind::Response,
        RewriteIssueKind::Dependency,
        RewriteIssueKind::Replay,
    ] {
        state.active_issue.as_mut().unwrap().kind = kind;
        assert!(dependency_issue(&state, &spec).is_ok());
        assert!(
            validate_plan_evidence(
                Path::new("/missing-target"),
                &state,
                "issue-dependency",
                "evidence-dirty-clusters",
                &spec
            )
            .is_err()
        );
    }
}
