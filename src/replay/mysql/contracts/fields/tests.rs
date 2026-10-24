use super::*;
use serde_json::json;

fn compiled_rule(delivery: bool) -> CompiledRule {
    let mut value = json!({"id":"tasks-time","surface":"dependency.response","match":{
        "resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"tables":["tasks"]},
        "slot":{"sql_field":"updated_at"},"codec":"scalar","contract":{"":{"relative_time":"sql_datetime"}},
        "proof":{"source":"models.py:read","fact":"This physical result column preserves the request-relative timestamp"}});
    if delivery {
        value["delivery"] = json!({"rebase_time":[""]});
    }
    crate::policy::parse_and_compile_policy(
        &json!({"format":"traffic-policy/v2","rules":[value]}).to_string(),
    )
    .unwrap()
    .rules
    .remove(0)
}

fn response() -> RecordedMysqlResponse {
    serde_json::from_value(json!({"status":"resultset","columns":[
        {"name":"changed","database":"app","table":"tasks","column":"updated_at","family":"datetime","sql_type":"DATETIME"},
        {"name":"other","database":"archive","table":"tasks","column":"updated_at","family":"datetime","sql_type":"DATETIME"}
    ],"rows":[[{"kind":"datetime","value":"2020-01-01 00:00:01"},{"kind":"datetime","value":"2020-01-01 00:00:02"}]],"row_count":1,"rows_truncated":false})).unwrap()
}

#[test]
fn full_physical_origins_distinguish_same_named_columns_and_survive_aliases() {
    let rule = compiled_rule(false);
    let response = response();
    assert_eq!(
        response_indices(&response, &rule, None, Some("other")).unwrap(),
        vec![0]
    );
    let values = response_values(&response, &rule, None, Some("other")).unwrap();
    assert_eq!(
        values,
        vec![(b"0:0".to_vec(), b"\"2020-01-01 00:00:01\"".to_vec())]
    );
}

#[test]
fn old_recordings_require_direct_projection_proof_and_reject_ambiguous_wildcards() {
    let rule = compiled_rule(false);
    let mut response = response();
    for column in &mut response.columns {
        column.database = None;
    }
    let sql = "SELECT a.updated_at AS changed, b.updated_at AS other FROM app.tasks a JOIN archive.tasks b ON a.id=b.id";
    assert_eq!(
        response_indices(&response, &rule, Some(sql), Some("other")).unwrap(),
        vec![0]
    );
    assert!(
        response_indices(&response, &rule, Some("SELECT * FROM tasks"), Some("app"))
            .unwrap()
            .is_empty()
    );
    response.columns[0].database = Some("archive".into());
    response.columns[0].table = None;
    assert!(
        response_indices(&response, &rule, Some(sql), Some("app"))
            .unwrap()
            .is_empty(),
        "fallback must retain a known wire schema even when the table origin is missing"
    );
    response.columns[0].database = None;
    response.columns[0].table = Some("unrelated".into());
    assert!(
        response_indices(&response, &rule, Some(sql), Some("app"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn explicit_scalar_delivery_changes_only_selected_native_cells() {
    let rule = compiled_rule(true);
    let response = response();
    let clocks = AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2026-01-01T00:00:00Z".parse().unwrap()),
        },
        ..Default::default()
    };
    let changed =
        super::super::materialize_response(&response, &[&rule], clocks, None, None).unwrap();
    assert_eq!(changed.rows[0][0].value, Some(json!("2026-01-01 00:00:01")));
    assert_eq!(changed.rows[0][1], response.rows[0][1]);
    assert_eq!(changed.columns, response.columns);
    let no_delivery = compiled_rule(false);
    let unchanged =
        super::super::materialize_response(&response, &[&no_delivery], clocks, None, None).unwrap();
    assert_eq!(unchanged, response);
}

#[test]
fn scalar_response_null_requires_an_explicit_exact_branch_and_rejects_type_changes() {
    let rule = compiled_rule(false);
    let mut source = response();
    source.rows[0][0] = RecordedMysqlValue {
        kind: "null".into(),
        value: None,
        raw: None,
    };
    let ordinary = super::super::validate_response(
        &source,
        &source,
        &[&rule],
        AnchorClocks::default(),
        None,
        None,
    )
    .unwrap();
    assert!(
        !ordinary.passed(),
        "a present scalar NULL must not bypass an active time contract"
    );

    let mut declaration = serde_json::to_value(&rule.rule).unwrap();
    declaration["contract"][""] = json!({"kind":"conditional",
        "when":{"relative_pointer":".","not_in":[null]},
        "contract":{"relative_time":"sql_datetime"}});
    let nullable = crate::policy::parse_and_compile_policy(
        &json!({"format":"traffic-policy/v2","rules":[declaration]}).to_string(),
    )
    .unwrap()
    .rules
    .remove(0);
    let same = super::super::validate_response(
        &source,
        &source,
        &[&nullable],
        AnchorClocks::default(),
        None,
        None,
    )
    .unwrap();
    assert!(
        same.passed(),
        "an inactive NULL branch preserves the exact native value"
    );
    let mut target = source.clone();
    target.rows[0][0] = response().rows[0][0].clone();
    for (source, target) in [(&source, &target), (&target, &source)] {
        assert!(
            !super::super::validate_response(
                source,
                target,
                &[&nullable],
                AnchorClocks::default(),
                None,
                None,
            )
            .unwrap()
            .passed(),
            "NULL/value changes must stay strict in both directions"
        );
    }
}

#[test]
fn native_null_encoded_columns_do_not_invent_a_decoded_payload() {
    let value = RecordedMysqlValue {
        kind: "null".into(),
        value: None,
        raw: None,
    };
    assert!(
        value_bytes(&value, &crate::policy::Codec::Json)
            .unwrap()
            .is_none()
    );
}
