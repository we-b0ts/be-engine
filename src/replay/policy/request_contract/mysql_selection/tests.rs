use super::*;
use crate::policy::Surface;
use crate::replay::{RecordedMysqlValue, ReplaySessionIdentity};
use serde_json::json;

fn selection(templates: &[(&str, &str)]) -> MysqlSelection {
    MysqlSelection {
        templates: templates
            .iter()
            .map(|(id, sql)| {
                (
                    (*id).into(),
                    SqlValueTemplate::new(sql, &[], &[], None).unwrap(),
                )
            })
            .collect(),
        ..Default::default()
    }
}

fn record(sql: &str, params: Option<Vec<RecordedMysqlValue>>) -> RecordedMysqlExchange {
    serde_json::from_value(json!({
        "command": if params.is_some() { "COM_STMT_EXECUTE" } else { "COM_QUERY" },
        "sql": sql,
        "params": params,
        "response": { "status": "ok" }
    }))
    .unwrap()
}

fn parameter(kind: &str, value: Value) -> RecordedMysqlValue {
    RecordedMysqlValue {
        kind: kind.into(),
        value: Some(value),
        raw: None,
    }
}

#[test]
fn unrelated_verbs_and_unknown_rules_skip_all_statement_parsing() {
    let selection = selection(&[("time", "UPDATE entries SET stamp=? WHERE id=7")]);
    for sql in [
        "SELECT payload FROM entries WHERE id=7",
        "ROLLBACK ",
        "COMMIT ",
        "BEGIN ",
    ] {
        assert!(!selection.matches("time", &record(sql, None), &mut None));
    }
    assert!(!selection.matches(
        "absent",
        &record("UPDATE entries SET stamp=1 WHERE id=7", None),
        &mut None
    ));
    assert_eq!(selection.parses.load(Ordering::Relaxed), 0);
    assert!(selection.statements.lock().unwrap().entries.is_empty());
}

#[test]
fn rules_and_repeated_candidates_share_raw_tokens_without_materialized_value_cache() {
    let selection = selection(&[
        ("seven", "UPDATE entries SET stamp=? WHERE id=7"),
        ("eight", "UPDATE entries SET stamp=? WHERE id=8"),
    ]);
    let sql = "UPDATE entries SET stamp=? WHERE id=?";
    for id in [7, 8, 7] {
        let record = record(
            sql,
            Some(vec![
                parameter("integer", json!(1000)),
                parameter("integer", json!(id)),
            ]),
        );
        let mut statement = None;
        assert_eq!(selection.matches("seven", &record, &mut statement), id == 7);
        let bound = statement.as_ref().unwrap().as_ref().unwrap().clone();
        assert_eq!(selection.matches("eight", &record, &mut statement), id == 8);
        assert!(Arc::ptr_eq(
            &bound,
            statement.as_ref().unwrap().as_ref().unwrap()
        ));
    }
    assert_eq!(selection.parses.load(Ordering::Relaxed), 1);
    let raw = selection.statement_tokens(sql).unwrap();
    assert_eq!(
        raw.iter()
            .filter(|token| **token == Token::Placeholder)
            .count(),
        2
    );
    assert!(Arc::ptr_eq(&raw, &selection.statement_tokens(sql).unwrap()));
    for params in [
        vec![],
        vec![parameter("integer", json!(1))],
        vec![
            parameter("integer", json!(1)),
            parameter("integer", json!(7)),
            parameter("integer", json!(9)),
        ],
        vec![
            parameter("unsupported", json!(1)),
            parameter("integer", json!(7)),
        ],
        vec![
            parameter("integer", json!(1)),
            parameter("string", json!("7")),
        ],
    ] {
        assert!(!selection.matches("seven", &record(sql, Some(params)), &mut None));
    }
    assert_eq!(selection.parses.load(Ordering::Relaxed), 1);
}

#[test]
fn negative_parse_results_are_cached_but_oversized_statements_are_not_retained() {
    let selection = selection(&[("time", "UPDATE entries SET stamp=? WHERE id=7")]);
    let invalid = "UPDATE entries SET stamp=1 WHERE id=7; DELETE FROM entries";
    for _ in 0..3 {
        assert!(!selection.matches("time", &record(invalid, None), &mut None));
    }
    assert_eq!(selection.parses.load(Ordering::Relaxed), 1);
    assert!(matches!(
        selection.statements.lock().unwrap().get(invalid),
        Some(None)
    ));
    let oversized = format!("UPDATE {}", " ".repeat(MAX_STATEMENT_BYTES));
    assert!(selection.statement_tokens(&oversized).is_none());
    assert_eq!(selection.parses.load(Ordering::Relaxed), 1);
    assert_eq!(selection.statements.lock().unwrap().entries.len(), 1);
}

#[test]
fn large_attachment_statements_match_without_exceeding_cache_retention() {
    let selection = selection(&[(
        "attachment",
        "UPDATE attachments SET payload=?, status='READY' WHERE id=7",
    )]);
    let prefix = "UPDATE attachments SET payload='";
    let suffix = "', status='READY' WHERE id=7";
    for bytes in [1_314_248, 8 * 1024 * 1024] {
        let sql = format!(
            "{prefix}{}{suffix}",
            "x".repeat(bytes - prefix.len() - suffix.len())
        );
        assert_eq!(sql.len(), bytes);
        assert!(selection.matches("attachment", &record(&sql, None), &mut None));
        let cache = selection.statements.lock().unwrap();
        assert!(cache.bytes <= MAX_BYTES);
        if bytes == 8 * 1024 * 1024 {
            assert!(cache.get(&sql).is_none());
        }
    }
}

#[test]
fn statement_cache_evicts_by_entry_and_retained_byte_limits() {
    let selection = MysqlSelection::default();
    for id in 0..=MAX_ENTRIES {
        assert!(
            selection
                .statement_tokens(&format!("SELECT {id}"))
                .is_some()
        );
    }
    {
        let statements = selection.statements.lock().unwrap();
        assert_eq!(statements.entries.len(), MAX_ENTRIES);
        assert!(statements.get("SELECT 0").is_none());
        assert_eq!(statements.order.len(), MAX_ENTRIES);
        assert!(statements.bytes <= MAX_BYTES);
    }
    let large = "x".repeat(400_000);
    for id in 0..12 {
        assert!(
            selection
                .statement_tokens(&format!("SELECT '{large}', {id}"))
                .is_some()
        );
    }
    let statements = selection.statements.lock().unwrap();
    assert!(statements.entries.len() < 12);
    assert_eq!(statements.order.len(), statements.entries.len());
    assert!(statements.bytes <= MAX_BYTES);
    assert_eq!(
        statements.bytes,
        statements
            .entries
            .values()
            .map(|entry| entry.bytes)
            .sum::<usize>()
    );
}

#[test]
fn concurrent_insert_keeps_the_first_raw_parse_and_retires_the_other_outside_the_lock() {
    let sql: Arc<str> = "SELECT 7".into();
    let tokens = Arc::new(bounded_statement_tokens(&sql).unwrap());
    let mut statements = Statements::default();
    let bytes = statement_bytes(&sql, Some(&tokens));
    let (first, retired) = statements.insert(sql.clone(), Some(tokens.clone()), bytes);
    assert!(Arc::ptr_eq(&tokens, first.as_ref().unwrap()));
    assert!(retired.is_empty());
    let duplicate = Arc::new((*tokens).clone());
    let (second, retired) = statements.insert(sql, Some(duplicate.clone()), bytes);
    assert!(Arc::ptr_eq(&tokens, second.as_ref().unwrap()));
    assert_eq!(retired.len(), 1);
    assert!(Arc::ptr_eq(
        &duplicate,
        retired[0].1.tokens.as_ref().unwrap()
    ));
    assert_eq!(statements.entries.len(), 1);
    assert_eq!(statements.bytes, bytes);
}

fn runtime(native: bool) -> RequestContracts {
    let effect = if native {
        "  effect:\n    kind: mysql_values\n    values:\n      0: {relative_time: unix_seconds}\n"
    } else {
        "  surface: dependency.request\n  slot: {sql_value: 0}\n  codec: json\n  contract:\n    /stamp: {kind: time, format: unix_seconds, relation: preserve_offset}\n"
    };
    let policy = crate::policy::parse_policy(&format!(
        r#"format: traffic-policy/v1
rules:
- id: time
  match:
    api: POST /entries/*
    resource: {{protocol: mysql, endpoint: 'db.test:3306', database: app, username: writer}}
    operation: COM_QUERY
    sql: UPDATE entries SET stamp=? WHERE id=7
  when:
    request_body_json:
      /enabled: {{equals: true}}
{effect}  proof: {{source: 'src/entries.rs:10-20', fact: 'Source writes request-relative seconds'}}
"#
    ))
    .unwrap();
    let mut runtime = RequestContracts::default();
    runtime
        .configure_compiled(Some(Arc::new(
            crate::policy::compile_policy(&policy).unwrap(),
        )))
        .unwrap();
    runtime.state.lock().unwrap().cases.insert(
        "case".into(),
        CaseAnchor {
            method: "POST".into(),
            path: "/entries/7".into(),
            source_body: Some(json!({"enabled": true})),
            recorded: DateTime::from_timestamp(1000, 0),
            actual: DateTime::from_timestamp(2000, 0),
            conditions: Default::default(),
            dir: PathBuf::new(),
        },
    );
    runtime
}

#[test]
fn cache_hits_keep_api_case_condition_resource_command_and_stable_sql_guards_live() {
    for native in [false, true] {
        let runtime = runtime(native);
        let identity = ReplaySessionIdentity {
            target: Some(TargetKey {
                host: "DB.TEST".into(),
                port: 3306,
            }),
            database: Some("app".into()),
            username: Some("writer".into()),
        };
        let record = record("UPDATE entries SET stamp=1000 WHERE id=7", None);
        let selected = |case, identity: &ReplaySessionIdentity, record: &RecordedMysqlExchange| {
            if native {
                runtime
                    .mysql_native_value_rules(case, identity, record)
                    .len()
            } else {
                runtime
                    .mysql_compiled_rules(Surface::DependencyRequest, case, identity, record)
                    .len()
            }
        };
        assert_eq!(selected(Some("case"), &identity, &record), 1);
        assert_eq!(selected(None, &identity, &record), 0);
        assert_eq!(selected(Some("absent"), &identity, &record), 0);
        for changed in [
            ReplaySessionIdentity {
                database: Some("other".into()),
                ..identity.clone()
            },
            ReplaySessionIdentity {
                username: Some("reader".into()),
                ..identity.clone()
            },
            ReplaySessionIdentity {
                target: Some(TargetKey {
                    host: "other.test".into(),
                    port: 3306,
                }),
                ..identity.clone()
            },
            ReplaySessionIdentity {
                target: Some(TargetKey {
                    host: "db.test".into(),
                    port: 3307,
                }),
                ..identity.clone()
            },
        ] {
            assert_eq!(selected(Some("case"), &changed, &record), 0);
        }
        let mut changed = record.clone();
        changed.command = "COM_STMT_EXECUTE".into();
        assert_eq!(selected(Some("case"), &identity, &changed), 0);
        changed = record.clone();
        changed.sql = Some("UPDATE entries SET stamp=1000 WHERE id=8".into());
        assert_eq!(selected(Some("case"), &identity, &changed), 0);
        for (method, path, body) in [
            ("PUT", "/entries/7", Some(json!({"enabled": true}))),
            ("POST", "/other/7", Some(json!({"enabled": true}))),
            ("POST", "/entries/7", Some(json!({"enabled": false}))),
            ("POST", "/entries/7", Some(json!({"enabled": "true"}))),
            ("POST", "/entries/7", None),
        ] {
            {
                let mut state = runtime.state.lock().unwrap();
                let anchor = state.cases.get_mut("case").unwrap();
                anchor.method = method.into();
                anchor.path = path.into();
                anchor.source_body = body;
            }
            assert_eq!(selected(Some("case"), &identity, &record), 0);
        }
    }
}

#[test]
fn compiled_templates_are_shared_by_runtime_clones_and_reset_on_policy_reconfiguration() {
    let mut runtime = runtime(false);
    assert_eq!(runtime.mysql_selection.templates.len(), 1);
    let clone = runtime.clone();
    assert!(Arc::ptr_eq(
        &runtime.mysql_selection,
        &clone.mysql_selection
    ));
    runtime.configure_compiled(None).unwrap();
    assert!(runtime.mysql_selection.templates.is_empty());
    assert!(!Arc::ptr_eq(
        &runtime.mysql_selection,
        &clone.mysql_selection
    ));
    assert_eq!(clone.mysql_selection.templates.len(), 1);
    let policy = crate::policy::parse_policy(
        r#"format: traffic-policy/v1
rules:
- id: response-set
  surface: api.response
  match: {api: GET /entries}
  slot: body
  codec: json
  contract: {/entries: {kind: unordered}}
  proof: {source: 'src/entries.rs:20-30', fact: 'Response is an unordered collection'}
"#,
    )
    .unwrap();
    runtime
        .configure_compiled(Some(Arc::new(
            crate::policy::compile_policy(&policy).unwrap(),
        )))
        .unwrap();
    assert!(runtime.mysql_selection.templates.is_empty());
}
