use super::*;

#[test]
fn literal_recording_and_public_selectors_preserve_slashes_and_scope() {
    for path in ["/api/v1/auth/tokens/", "/api//items"] {
        let api = format!("POST {path}").parse::<RecordingApi>().unwrap();
        assert_eq!(api.path_pattern(), path);
        assert_eq!(api.to_string(), format!("POST {path}"));
        assert_eq!(path.parse::<RecordingApiScope>().unwrap().to_string(), path);
        assert!(api.matches(&Method::POST, &path.parse().unwrap()));
        assert!(!api.matches(&Method::GET, &path.parse().unwrap()));
        let rules = [HttpGatewayRuleConfig {
            methods: vec!["POST".into()],
            path_prefixes: vec!["/api".into()],
            ..Default::default()
        }];
        validate_selection(std::slice::from_ref(&api), &rules).unwrap();
        let unrelated = [HttpGatewayRuleConfig {
            methods: vec!["POST".into()],
            path_prefixes: vec!["/other".into()],
            ..Default::default()
        }];
        assert!(validate_selection(std::slice::from_ref(&api), &unrelated).is_err());
        assert!(validate_selection(&[api.clone(), api], &rules).is_err());
    }
    validate_selection(
        &[
            "POST /api/a".parse().unwrap(),
            "POST /api/a/".parse().unwrap(),
            "POST /api/*".parse().unwrap(),
        ],
        &[],
    )
    .unwrap_err();
    validate_selection(
        &[
            "POST /api/a".parse().unwrap(),
            "POST /api/a/".parse().unwrap(),
        ],
        &[],
    )
    .unwrap();
    validate_selection(
        &[
            "POST /api/*".parse().unwrap(),
            "POST /api/a/".parse().unwrap(),
        ],
        &[],
    )
    .unwrap();
    assert!("POST /api/*/".parse::<RecordingApi>().is_err());
    assert!("MOTAN /service/method/".parse::<RecordingApi>().is_err());
}
