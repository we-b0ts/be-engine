use super::*;
use serde_json::json;

fn rule() -> ReplayDependencyRule {
    serde_json::from_value(json!({"id":"time","protocol":"http","target":{"host":"http.test","port":80},
        "case":{"method":"POST","path":"/windows/*"},
        "source_evidence":"Client:build generates related seconds, milliseconds and ISO time fields",
        "http":{"method":"POST","path":"/query","json":{"time":{
            "/seconds":{"time":"preserve_relative","format":"unix_seconds"},
            "/nested/ms":{"time":"preserve_relative","format":"unix_milliseconds"},
            "/iso":{"time":"preserve_relative","format":"rfc3339"}
        }}}})).unwrap()
}
fn clocks() -> RequestTimes {
    RequestTimes {
        source: DateTime::from_timestamp(1000, 0),
        target: DateTime::from_timestamp(2000, 0),
    }
}
fn values(seconds: f64) -> Value {
    json!({"seconds":seconds,"nested":{"ms":(seconds+300.0)*1000.0,"stable":true},
        "iso":DateTime::from_timestamp(seconds as i64, 250_000_000).unwrap().to_rfc3339(),"ordered":[1,2]})
}
#[test]
fn json_request_time_formats_share_one_shift_with_inclusive_tolerance() {
    let rule = rule();
    super::super::validate(&rule).unwrap();
    let http = rule.http.as_ref().unwrap();
    let source = values(1000.0).to_string();
    for (shift, passes) in [
        (0.0, true),
        (5.0, true),
        (-5.0, true),
        (6.0, false),
        (-6.0, false),
        (-1000.0, false),
    ] {
        assert_eq!(
            compare(
                http,
                source.as_bytes(),
                values(2000.0 + shift).to_string().as_bytes(),
                clocks()
            )
            .is_ok(),
            passes
        );
    }
    let mut actual = values(2000.0);
    actual["nested"]["ms"] = json!(2_301_000.0);
    assert!(
        compare(
            http,
            source.as_bytes(),
            actual.to_string().as_bytes(),
            clocks()
        )
        .is_err()
    );
    actual = values(2000.0);
    actual["seconds"] = json!(2000);
    assert!(
        compare(
            http,
            source.as_bytes(),
            actual.to_string().as_bytes(),
            clocks()
        )
        .is_err()
    );
    let actual = values(2000.0).to_string();
    for clocks in [
        RequestTimes {
            source: None,
            ..clocks()
        },
        RequestTimes {
            target: None,
            ..clocks()
        },
    ] {
        assert!(compare(http, source.as_bytes(), actual.as_bytes(), clocks).is_err());
    }
    assert!(
        compare(
            http,
            br#"{"seconds":1000.0,"seconds":1000.0}"#,
            actual.as_bytes(),
            clocks()
        )
        .is_err()
    );
    assert!(
        compare(
            http,
            source.as_bytes(),
            &vec![b' '; 1024 * 1024 + 1],
            clocks()
        )
        .is_err()
    );
}

#[test]
fn json_request_time_config_rejects_unbounded_locations_and_ambiguous_ownership() {
    let original = serde_json::to_value(rule()).unwrap();
    for pointer in ["", "/*", "/nested", "/bad~2pointer"] {
        let mut value = original.clone();
        value["http"]["json"]["time"][pointer] =
            json!({"time":"preserve_relative","format":"unix_seconds"});
        assert!(
            super::super::validate(&serde_json::from_value(value).unwrap()).is_err(),
            "{pointer}"
        );
    }
    for field in ["case", "target"] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(field);
        let rejected = serde_json::from_value(value)
            .map(|rule| super::super::validate(&rule).is_err())
            .unwrap_or(true);
        assert!(rejected);
    }
    let mut value = original.clone();
    value["http"]["json"]["time"]["/seconds"]["tolerance"] = json!("30s");
    assert!(super::super::validate(&serde_json::from_value(value).unwrap()).is_err());
    let mut value = original.clone();
    value["http"]["json"]["unordered"] =
        json!([{"pointer":"/ordered","source_evidence":"Client:build sends an unordered set"}]);
    assert!(super::super::validate(&serde_json::from_value(value).unwrap()).is_err());
    let mut document: super::super::super::config::ReplayPolicyDocument =
        serde_yaml::from_str("version: 3\nexpected_response: assertions_only\n").unwrap();
    document.dependency_rules = vec![rule(), rule()];
    document.dependency_rules[1].id = "other".into();
    assert!(super::super::validate_overlaps(&document).is_err());
    document.dependency_rules[1]
        .case_selector
        .as_mut()
        .unwrap()
        .method = "GET".into();
    super::super::validate_overlaps(&document).unwrap();
    document.dependency_rules[1]
        .case_selector
        .as_mut()
        .unwrap()
        .method = "POST".into();
    document.dependency_rules[1]
        .http
        .as_mut()
        .unwrap()
        .json
        .time
        .clear();
    assert!(super::super::validate_overlaps(&document).is_err());
}

#[test]
fn json_request_time_requires_exact_endpoint_inbound_case_and_dependency_method() {
    let mut state = State::default();
    state.cases.insert(
        "case".into(),
        CaseAnchor {
            method: "POST".into(),
            path: "/windows/1".into(),
            recorded: None,
            actual: None,
            dir: PathBuf::new(),
        },
    );
    let runtime = RequestContracts {
        rules: Arc::new(vec![rule()]),
        state: Arc::new(Mutex::new(state)),
        ..Default::default()
    };
    let source = values(1000.0).to_string();
    let actual = values(2000.0).to_string();
    let target = TargetKey {
        host: "http.test".into(),
        port: 80,
    };
    let check = |case, target: &TargetKey, method, path| {
        runtime.preview_http_json_time(
            case,
            target,
            method,
            path,
            path,
            source.as_bytes(),
            &BTreeMap::new(),
            actual.as_bytes(),
            &BTreeMap::new(),
            clocks(),
        )
    };
    assert!(check("case", &target, "POST", "/query").unwrap().is_ok());
    assert!(check("other", &target, "POST", "/query").is_none());
    assert!(
        check(
            "case",
            &TargetKey {
                host: "other.test".into(),
                port: 80
            },
            "POST",
            "/query"
        )
        .is_none()
    );
    assert!(
        check(
            "case",
            &TargetKey {
                port: 81,
                ..target.clone()
            },
            "POST",
            "/query"
        )
        .is_none()
    );
    assert!(check("case", &target, "GET", "/query").is_none());
    assert!(check("case", &target, "POST", "/other").is_none());
    runtime
        .state
        .lock()
        .unwrap()
        .cases
        .get_mut("case")
        .unwrap()
        .method = "GET".into();
    assert!(check("case", &target, "POST", "/query").is_none());
}
