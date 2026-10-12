use super::*;
use serde_json::json;

fn response() -> RecordedMysqlResponse {
    serde_json::from_value(json!({"status":"resultset","columns":[
        {"name":"expires_at","column":"expires_at","family":"datetime","sql_type":"DATETIME"},
        {"name":"owner","family":"string","sql_type":"VARCHAR"}],
        "rows":[[{"kind":"datetime","value":"2020-01-01 00:05:00.123456"},{"kind":"string","value":"stable"}], [{"kind":"null"},{"kind":"string","value":"other"}]]})).unwrap()
}

#[test]
fn mysql_response_time_shift_preserves_relative_expiry_nulls_and_stable_cells() {
    let mut response = response();
    response.rows[0][0].raw = Some(ReplayBodyCapture {
        encoding: "utf8".into(),
        data: "2020-01-01 00:05:00.123456".into(),
    });
    let epoch = parse_datetime("1970-01-01 00:00:00").unwrap();
    response.rows.push(vec![
        serde_json::from_value(json!({"kind":"datetime","value":"1970-01-01 00:00:00.000000"}))
            .unwrap(),
        response.rows[0][1].clone(),
    ]);
    let fields = BTreeMap::from([("expires_at".into(), BTreeSet::from([epoch]))]);
    let times = crate::replay::assertion::RequestTimes {
        source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
        target: Some("2026-10-12T01:00:00Z".parse().unwrap()),
    };
    let shifted = shift_response(&response, &fields, times).unwrap();
    assert_eq!(
        shifted.rows[0][0].value,
        Some(json!("2026-10-12 01:05:00.123456"))
    );
    assert_eq!(shifted.rows[0][1], response.rows[0][1]);
    assert_eq!(
        mysql_value_bytes(&shifted.rows[0][0]).unwrap(),
        b"2026-10-12 01:05:00.123456"
    );
    assert_eq!(shifted.rows[1], response.rows[1]);
    assert_eq!(shifted.rows[2], response.rows[2]);
    assert_eq!(
        response.rows[0][0].value,
        Some(json!("2020-01-01 00:05:00.123456"))
    );
    assert!(
        shift_response(
            &response,
            &fields,
            crate::replay::assertion::RequestTimes::default()
        )
        .is_err()
    );
    let mut invalid = response.clone();
    invalid.rows[1][0].kind = "datetime".into();
    invalid.rows[1][0].value = Some(json!("invalid"));
    assert!(shift_response(&invalid, &fields, times).is_err());
    invalid = response.clone();
    invalid.columns.push(invalid.columns[0].clone());
    assert!(shift_response(&invalid, &fields, times).is_err());
}
