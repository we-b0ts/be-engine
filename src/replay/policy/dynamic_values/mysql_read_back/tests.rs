use super::*;
use serde_json::json;

fn definition() -> Value {
    json!({"id":"block","match":{"api":"POST /api","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},"operation":"SET","key":{"kind":"exact","value":"current"}},"effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},"references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}},{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"}}],"mysql_read_back":[{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},"sql":"SELECT payload FROM {{table}} WHERE id=?","table_series":{"prefix":"results_","start":0,"end":9,"width":4},"column":"payload","json_pointers":["/blocks/*/id","/blocks/*/key"],"proof":{"source":"store.py:read","fact":"Source reads stored block identities and derived keys"}}]},"proof":{"source":"store.py:create","fact":"Source generates and retains a block identity"}})
}

fn capture() -> Value {
    json!({"event_type":"redis_exchange","timestamp":"2026-10-20T00:00:00Z","duration_ms":0,"target_host":"cache.test","target_port":6379,"database":0,"command":"SET","args":[{"encoding":"utf8","data":"current"},{"encoding":"utf8","data":"old"}],"response":{"encoding":"utf8","data":"+OK\r\n"},"outcome":"response","replay_safe":true})
}

fn record() -> RecordedMysqlExchange {
    serde_json::from_value(json!({"timestamp":"2026-10-20T00:00:01Z","duration_ms":0,"command":"COM_QUERY","sql":"SELECT payload FROM results_0001 WHERE id=7","response":{"status":"resultset","columns":[{"name":"payload_alias","column":"payload","family":"text","sql_type":"JSON"}],"rows":[[{"kind":"string","value":json!({"blocks":[{"id":"old","key":"content:old","stable":7},{"id":"older","key":"content:older","stable":8}],"unselected":"old"}).to_string()}]]}})).unwrap()
}

fn fixture() -> DynamicValues {
    fixture_with(definition())
}

fn fixture_with(mut definition: Value) -> DynamicValues {
    definition["effect"]["mysql_read_back"][0]["templates"] =
        json!({"/blocks/*/key":"content:{value}"});
    let compiled = crate::policy::compile_policy(
        &serde_json::from_value(json!({"format":"traffic-policy/v2","rules":[definition]}))
            .unwrap(),
    )
    .unwrap();
    let projection =
        super::super::super::native_projection::project_native(&compiled.native).unwrap();
    let mut runtime = DynamicValues::new(
        projection.document.dynamic_values,
        BTreeMap::from([("case".into(), "/api".into())]),
    );
    runtime.configure_native(&compiled.native);
    runtime.set_request("case", &json!({"method":"POST","uri":"/api"}));
    runtime
        .observe_source("case", capture().to_string().as_bytes())
        .unwrap();
    let pending = runtime
        .redis(
            Some("case"),
            &TargetKey {
                host: "cache.test".into(),
                port: 6379,
            },
            0,
            "SET",
            &[b"current".to_vec(), b"old".to_vec()],
            &[b"current".to_vec(), b"new".to_vec()],
        )
        .unwrap()
        .unwrap();
    runtime.commit("case", pending.decision);
    runtime
}

#[test]
fn mysql_identity_read_back_binds_derived_aliases_across_bounded_text_and_prepared_shards() {
    let mut definition = definition();
    definition["effect"]["mysql_read_back"][0]["sql"] =
        json!("SELECT {{table}}.payload AS {{table}}_payload FROM {{table}} WHERE {{table}}.id=?");
    let runtime = fixture_with(definition);
    for table in ["results_0000", "results_0009"] {
        for command in ["COM_QUERY", "COM_STMT_EXECUTE"] {
            let mut record = record();
            record.command = command.into();
            record.sql = Some(format!(
                "SELECT {table}.payload AS {table}_payload FROM {table} WHERE {table}.id={}",
                if command == "COM_QUERY" { "7" } else { "?" }
            ));
            if command == "COM_STMT_EXECUTE" {
                record.params = Some(vec![crate::replay::RecordedMysqlValue {
                    kind: "integer".into(),
                    value: Some(json!(7)),
                    raw: None,
                }]);
            }
            record.response.columns[0].name = format!("{table}_payload");
            let original = serde_json::to_vec(&record.response).unwrap();
            let prepared = runtime
                .prepare_mysql_identity_delivery(
                    Some("case"),
                    &identity(),
                    &record,
                    &record.response,
                )
                .unwrap()
                .unwrap();
            let delivered = prepared.render(&record.response).unwrap();
            let value = json(&delivered.rows[0][0]).unwrap();
            assert_eq!(value["blocks"][0]["id"], "new");
            assert_eq!(value["blocks"][0]["key"], "content:new");
            assert_eq!(value["blocks"][0]["stable"], 7);
            assert_eq!(value["blocks"][1]["id"], "older");
            assert_eq!(serde_json::to_vec(&record.response).unwrap(), original);
        }
    }
    for sql in [
        "SELECT results_0000.payload AS results_0009_payload FROM results_0000 WHERE results_0000.id=7",
        "SELECT results_0009.payload AS results_0000_payload FROM results_0000 WHERE results_0000.id=7",
        "SELECT results_0010.payload AS results_0010_payload FROM results_0010 WHERE results_0010.id=7",
    ] {
        let mut record = record();
        record.sql = Some(sql.into());
        assert!(
            runtime
                .prepare_mysql_identity_delivery(
                    Some("case"),
                    &identity(),
                    &record,
                    &record.response
                )
                .unwrap()
                .is_none(),
            "{sql}"
        );
    }
}

#[test]
fn mysql_identity_read_back_alias_family_rejects_overlapping_exact_result_owners() {
    let mut identity = definition();
    identity["effect"]["mysql_read_back"][0]["sql"] =
        json!("SELECT {{table}}.payload AS {{table}}_payload FROM {{table}} WHERE {{table}}.id=?");
    for (table, alias, conflict) in [
        ("results_0009", "results_0009_payload", true),
        ("results_0010", "results_0010_payload", false),
        ("results_0009", "other_payload", false),
    ] {
        let other = json!({
            "id":"other", "surface":"dependency.response",
            "match":{"api":"POST /api", "resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},"operation":"COM_QUERY",
                "sql":format!("SELECT {table}.payload AS {alias} FROM {table} WHERE {table}.id=?")},
            "slot":{"sql_column":"payload"}, "codec":"json",
            "contract":{"/blocks/*/id":{"relative_time":"rfc3339"}},
            "proof":{"source":"other.py:1","fact":"Another contract selects the stored identity leaf"}
        });
        let policy = serde_json::from_value(
            json!({"format":"traffic-policy/v2","rules":[identity.clone(),other]}),
        )
        .unwrap();
        assert_eq!(
            crate::policy::compile_policy(&policy).is_err(),
            conflict,
            "{table}/{alias}"
        );
    }
}

fn identity() -> ReplaySessionIdentity {
    ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.test".into(),
            port: 3306,
        }),
        database: Some("app".into()),
        username: Some("writer".into()),
    }
}

#[test]
fn mysql_identity_read_back_rebases_only_selected_causal_case_bound_leaves() {
    let runtime = fixture();
    let record = record();
    let source = serde_json::to_vec(&record.response).unwrap();
    let prepared = runtime
        .prepare_mysql_identity_delivery(Some("case"), &identity(), &record, &record.response)
        .unwrap()
        .unwrap();
    assert!(runtime.mysql_read_back_report().is_empty());
    let delivered = prepared.render(&record.response).unwrap();
    let value = json(&delivered.rows[0][0]).unwrap();
    assert_eq!(value["blocks"][0]["id"], "new");
    assert_eq!(value["blocks"][0]["key"], "content:new");
    assert_eq!(value["blocks"][1]["id"], "older");
    assert_eq!(value["unselected"], "old");
    assert_eq!(value["blocks"][0]["stable"], 7);
    prepared.commit(&runtime, &delivered).unwrap();
    assert_eq!(runtime.mysql_read_back_report()[0].json_pointers.len(), 2);
    assert_eq!(serde_json::to_vec(&record.response).unwrap(), source);
    runtime.begin_case("case");
    assert!(runtime.mysql_read_back_report().is_empty());
    assert!(
        runtime
            .prepare_mysql_identity_delivery(Some("case"), &identity(), &record, &record.response)
            .unwrap()
            .is_none()
    );
}

#[test]
fn mysql_identity_read_back_keeps_resource_table_method_case_and_source_causality_strict() {
    let runtime = fixture();
    for scenario in [
        "user",
        "database",
        "endpoint",
        "table",
        "predicate-shape",
        "method",
        "case",
        "future-capture",
        "truncated",
        "ambiguous-column",
        "duplicate-json",
    ] {
        let mut record = record();
        let mut identity = identity();
        let mut case = Some("case");
        match scenario {
            "user" => identity.username = Some("reader".into()),
            "database" => identity.database = Some("another".into()),
            "endpoint" => identity.target.as_mut().unwrap().port = 3307,
            "table" => record.sql = Some("SELECT payload FROM results_0010 WHERE id=7".into()),
            "predicate-shape" => {
                record.sql = Some("SELECT payload FROM results_0001 WHERE tenant=7".into())
            }
            "method" => record.command = "COM_PING".into(),
            "case" => case = Some("another"),
            "future-capture" => record.timestamp = Some("2026-10-19T00:00:00Z".parse().unwrap()),
            "truncated" => record.response.rows_truncated = true,
            "ambiguous-column" => record
                .response
                .columns
                .push(record.response.columns[0].clone()),
            "duplicate-json" => {
                record.response.rows[0][0].value = Some(json!("{\"blocks\":[],\"blocks\":[]}"))
            }
            _ => unreachable!(),
        }
        let result =
            runtime.prepare_mysql_identity_delivery(case, &identity, &record, &record.response);
        if matches!(
            scenario,
            "truncated" | "ambiguous-column" | "duplicate-json"
        ) {
            assert!(result.is_err(), "{scenario}");
        } else {
            assert!(result.unwrap().is_none(), "{scenario}");
        }
        assert!(runtime.mysql_read_back_report().is_empty());
    }
}

#[test]
fn mysql_identity_read_back_admission_rejects_unbounded_unowned_and_overlapping_delivery() {
    for scenario in [
        "resource",
        "write",
        "multi-statement",
        "root",
        "duplicate",
        "no-table-bound",
        "missing-proof",
        "overlap",
    ] {
        let mut rule = definition();
        let read = &mut rule["effect"]["mysql_read_back"][0];
        match scenario {
            "resource" => read["resource"]["database"] = json!("other"),
            "write" => read["sql"] = json!("DELETE FROM {{table}} WHERE id=?"),
            "multi-statement" => {
                read["sql"] = json!("SELECT payload FROM {{table}} WHERE id=?; SELECT 1")
            }
            "root" => read["json_pointers"] = json!([""]),
            "duplicate" => read["json_pointers"] = json!(["/blocks/*/id", "/blocks/*/id"]),
            "no-table-bound" => {
                read.as_object_mut().unwrap().remove("table_series");
            }
            "missing-proof" => read["proof"] = json!({"source":"","fact":""}),
            _ => (),
        }
        let mut rules = vec![rule];
        if scenario == "overlap" {
            rules.push(json!({"id":"other","surface":"dependency.response","match":{"api":"POST /api","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},"operation":"COM_QUERY","sql":"SELECT payload FROM {{table}} WHERE id=?","table_series":{"prefix":"results_","start":0,"end":9,"width":4}},"slot":{"sql_column":"payload"},"codec":"json","contract":{"/blocks/*/id":{"relative_time":"rfc3339"}},"proof":{"source":"other.py:1","fact":"An incompatible owner selects the same leaf"}}));
        }
        let result = serde_json::from_value::<crate::policy::TrafficPolicy>(
            json!({"format":"traffic-policy/v2","rules":rules}),
        )
        .map_err(anyhow::Error::from)
        .and_then(|policy| crate::policy::compile_policy(&policy));
        assert!(result.is_err(), "{scenario}");
    }
}

#[test]
fn mysql_identity_read_back_never_uses_a_failed_source_capture_or_prefix_only_identity() {
    let runtime = fixture();
    let record = record();
    let prepared = runtime
        .prepare_mysql_identity_delivery(Some("case"), &identity(), &record, &record.response)
        .unwrap()
        .unwrap();
    let delivered = json(&prepared.render(&record.response).unwrap().rows[0][0]).unwrap();
    assert_eq!(delivered["blocks"][1]["id"], "older");
    assert_eq!(delivered["blocks"][1]["key"], "content:older");
    runtime.mysql_capture_clocks.lock().unwrap().clear();
    let mut failed = capture();
    failed["response_kind"] = json!("error");
    failed["response"]["data"] = json!("-ERR failed\r\n");
    runtime
        .observe_source("case", failed.to_string().as_bytes())
        .unwrap();
    assert!(
        runtime
            .prepare_mysql_identity_delivery(Some("case"), &identity(), &record, &record.response)
            .unwrap()
            .is_none()
    );
    assert!(runtime.mysql_read_back_report().is_empty());
}

#[test]
fn mysql_identity_read_back_uses_projected_rows_and_preserves_inactive_source_types() {
    let mut runtime = fixture();
    let mut record = record();
    let mut historical = record.response.rows[0].clone();
    historical[0].value = Some(json!(
        json!({"blocks":[{"id":"history","key":"content:history"}]}).to_string()
    ));
    record.response.rows.insert(0, historical);
    let mut projected = record.response.clone();
    projected.rows.remove(0);
    let prepared = runtime
        .prepare_mysql_identity_delivery(Some("case"), &identity(), &record, &projected)
        .unwrap()
        .unwrap();
    assert_eq!(
        json(&prepared.render(&projected).unwrap().rows[0][0]).unwrap()["blocks"][0]["id"],
        "new"
    );
    projected.columns.clear();
    projected.rows = vec![vec![]];
    assert!(
        runtime
            .prepare_mysql_identity_delivery(Some("case"), &identity(), &record, &projected)
            .unwrap()
            .is_none()
    );
    if let DynamicValueCapture::Redis { when, .. } =
        &mut Arc::make_mut(&mut runtime.rules)[0].capture
    {
        *when = Some(
            serde_json::from_value(json!({"relative_pointer":"../type","equals":"text"})).unwrap(),
        );
    }
    let mut record = self::record();
    record.response.rows[0][0].value = Some(json!(json!({"blocks":[{"type":"text","id":"old","key":"content:old"},{"type":"thinking","id":"old","key":"content:old"}]}).to_string()));
    let prepared = runtime
        .prepare_mysql_identity_delivery(Some("case"), &identity(), &record, &record.response)
        .unwrap()
        .unwrap();
    let value = json(&prepared.render(&record.response).unwrap().rows[0][0]).unwrap();
    assert_eq!(value["blocks"][0]["id"], "new");
    assert_eq!(value["blocks"][1]["id"], "old");
}
