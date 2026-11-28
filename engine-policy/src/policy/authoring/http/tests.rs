use super::*;

const CAPTURE: &str = r#"response_rewrite:
  - host: cs.example.test
    method: GET
    path: /executor-manager/sandboxes/*
    json_urls: [/base_url]
"#;

const PATHS: &str = r#"requests:
  - host: storage.example.test:9100
    method: PUT
    path: /attachments/objects/*
    path_identity:
      segment: 2
      template: '{nonce}_{created_at}_{user_id}_{attachment_id}'
      fields:
        nonce: {hex: 12}
        created_at: {timestamp: '%Y%m%d%H%M%S'}
        user_id: exact
        attachment_id: exact
      references: [storage, task_mysql]
  - host: storage.example.test:9100
    method: POST
    path: /attachments/objects/*
    api: POST /api/attachments/*
    path_identity:
      segment: 2
      template: '{nonce}_{created_at}_{user_id}_{attachment_id}'
      fields:
        nonce: {hex: 12}
        created_at: {timestamp: '%Y%m%d%H%M%S', mode: request_window}
        user_id: exact
        attachment_id: exact
      references: [storage, task_mysql]
"#;

const SIGV4: &str = r#"requests:
  - host: s3.hj4.1.intra.weibo.com:9100
    method: GET
    path: /wegent-archives
    query: 'location='
    authorization: {kind: aws_sigv4}
"#;

fn named() -> BTreeMap<String, ResourceDeclaration> {
    serde_yaml::from_str(
        r#"storage: {protocol: http, endpoint: 'storage.example.test:9100'}
task_mysql: {protocol: mysql, endpoint: 'db.example.test:3306', database: tasks, username: worker}
"#,
    )
    .unwrap()
}

fn parsed(raw: &str) -> Result<(Option<HttpPolicy>, Vec<NativeRule>)> {
    let document = serde_yaml::from_str(raw)?;
    let (headers, rules) = expand(Some(document), &named())?;
    Ok((
        headers,
        rules
            .into_iter()
            .map(serde_yaml::from_value)
            .collect::<std::result::Result<_, _>>()?,
    ))
}

fn rendered(rules: &[NativeRule], headers: Option<HttpPolicy>) -> Value {
    let mut root = Mapping::new();
    if let Some(headers) = headers {
        root.insert("http".into(), serde_yaml::to_value(headers).unwrap());
    }
    for rule in rules {
        assert!(compact(&rule.clone().into(), &named(), &mut root).unwrap());
    }
    root.into()
}

#[test]
fn url_capture_preserves_source_authority_and_ordinary_capture_filters() {
    let (headers, rules) = parsed(CAPTURE).unwrap();
    assert!(headers.is_none());
    let NativeEffect::CaptureHttpResponse(effect) = &rules[0].effect else {
        panic!("capture owner");
    };
    assert_eq!(rules[0].selector, NativeMatch::default());
    assert_eq!(effect.authorities, ["cs.example.test"]);
    assert_eq!(effect.methods, ["GET"]);
    assert_eq!(
        effect.path,
        CapturePath::Pattern {
            value: "/executor-manager/sandboxes/*".into()
        }
    );
    assert!(effect.status_codes.is_empty());
    assert!(effect.content_types.is_empty());
    let output = rendered(&rules, headers);
    let (_, restored) = expand(
        Some(serde_yaml::from_value(output["http"].clone()).unwrap()),
        &named(),
    )
    .unwrap();
    assert_eq!(
        restored,
        rules
            .iter()
            .map(|rule| serde_yaml::to_value(rule).unwrap())
            .collect::<Vec<_>>()
    );
    let text = serde_yaml::to_string(&output).unwrap();
    for forbidden in ["effect:", "match:", "authorities:", "contract:", "proof:"] {
        assert!(!text.contains(forbidden), "{text}");
    }
    let filtered = CAPTURE.replace(
        "json_urls: [/base_url]",
        "json_urls: [/base_url]\n    status_codes: [201]\n    content_types: [application/custom+json]",
    );
    let (_, rules) = parsed(&filtered).unwrap();
    let NativeEffect::CaptureHttpResponse(effect) = &rules[0].effect else {
        panic!("capture owner");
    };
    assert_eq!(effect.status_codes, [201]);
    assert_eq!(effect.content_types, ["application/custom+json"]);
    assert_eq!(
        serde_yaml::from_value::<HttpDocument>(rendered(&rules, None)["http"].clone())
            .unwrap()
            .response_rewrite[0]
            .status_codes,
        [201]
    );
}

#[test]
fn headers_keep_existing_normalization_and_do_not_create_a_second_runtime_owner() {
    let headers = "headers: {X-Amz-Date: {kind: time, formats: [amz_date]}}\n";
    let (http, rules) = parsed(&format!("{headers}{CAPTURE}")).unwrap();
    assert!(http.as_ref().unwrap().headers.contains_key("x-amz-date"));
    let output = rendered(&rules, http.clone());
    let (restored, _) = expand(
        Some(serde_yaml::from_value(output["http"].clone()).unwrap()),
        &named(),
    )
    .unwrap();
    assert_eq!(restored, http);
    assert!(parsed("{}").unwrap().0.is_some());
    assert!(parsed("headers: {}\n").unwrap().0.is_some());
    assert!(parsed("headers:\n  X-Amz-Date: {kind: time, formats: [amz_date]}\n  x-amz-date: {kind: time, formats: [amz_date]}\n").is_err());
}

#[test]
fn sigv4_request_round_trips_with_exact_query_and_runtime_scope() {
    let document = |http: &str| {
        format!(
            "format: traffic-policy/v3\nhttp:\n  {}\n",
            http.trim_end().replace('\n', "\n  ")
        )
    };
    let raw = document(SIGV4);
    let policy = crate::policy::parse_policy(&raw).unwrap();
    let compiled = crate::policy::compile_policy(&policy).unwrap();
    let [rule] = compiled.http.as_ref().unwrap().request_sigv4.as_slice() else {
        panic!("one compiled SigV4 request");
    };
    assert_eq!(rule.host, "s3.hj4.1.intra.weibo.com:9100");
    assert_eq!(rule.method.as_deref(), Some("GET"));
    assert_eq!(rule.path.as_deref(), Some("/wegent-archives"));
    assert_eq!(rule.query.as_deref(), Some("location="));

    let rendered = crate::policy::render_policy(&policy).unwrap();
    assert_eq!(
        crate::policy::parse_and_compile_policy(&rendered).unwrap(),
        compiled
    );
    let yaml: Value = serde_yaml::from_str(&rendered).unwrap();
    assert_eq!(
        yaml["http"]["requests"][0]["authorization"]["kind"],
        "aws_sigv4"
    );
    assert_eq!(yaml["http"]["requests"][0]["query"], "location=");
    assert!(yaml["http"].get("request_sigv4").is_none());

    let changed =
        crate::policy::parse_and_compile_policy(&raw.replace("location=", "location")).unwrap();
    assert_ne!(compiled.fingerprints.runtime, changed.fingerprints.runtime);
    assert_eq!(compiled.fingerprints.capture, changed.fingerprints.capture);
    assert_eq!(
        compiled.fingerprints.classification,
        changed.fingerprints.classification
    );

    for invalid in [
        raw.replace(":9100", ""),
        raw.replace("/wegent-archives", "/wegent-*"),
        raw.replace("kind: aws_sigv4", "kind: aws_sigv4a"),
        document(&format!(
            "{SIGV4}{}",
            SIGV4.strip_prefix("requests:\n").unwrap()
        )),
    ] {
        assert!(
            crate::policy::parse_policy(&invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn sigv4_request_round_trips_with_only_the_endpoint() {
    let raw = r#"format: traffic-policy/v3
http:
  requests:
    - host: s3.hj4.1.intra.weibo.com:9100
      authorization: {kind: aws_sigv4}
"#;
    let policy = crate::policy::parse_policy(raw).unwrap();
    let compiled = crate::policy::compile_policy(&policy).unwrap();
    let [rule] = compiled.http.as_ref().unwrap().request_sigv4.as_slice() else {
        panic!("one compiled SigV4 request");
    };
    assert_eq!(rule.host, "s3.hj4.1.intra.weibo.com:9100");
    assert_eq!(
        (&rule.method, &rule.path, &rule.query),
        (&None, &None, &None)
    );

    let rendered = crate::policy::render_policy(&policy).unwrap();
    assert_eq!(
        crate::policy::parse_and_compile_policy(&rendered).unwrap(),
        compiled
    );
    let yaml: Value = serde_yaml::from_str(&rendered).unwrap();
    let fields = yaml["http"]["requests"][0].as_mapping().unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields["authorization"]["kind"], "aws_sigv4");
}

#[test]
fn sigv4_and_path_identity_share_one_request_list() {
    let raw = format!("{SIGV4}{}", PATHS.strip_prefix("requests:\n").unwrap());
    let mut context = super::super::context();
    context.admit_native = &|_| Ok(());
    let parsed: HttpDocument = serde_yaml::from_str(&raw).unwrap();
    let (http, native) =
        traffic_policy_document::authoring::http::expand(Some(parsed), &named(), &context).unwrap();
    let mut root = Mapping::from_iter([("http".into(), serde_yaml::to_value(&http).unwrap())]);
    for rule in &native {
        assert!(
            traffic_policy_document::authoring::http::compact(
                &serde_yaml::from_value(rule.clone()).unwrap(),
                &named(),
                &mut root,
                &context,
            )
            .unwrap()
        );
    }
    let rendered = serde_yaml::from_value(root.remove("http").unwrap()).unwrap();
    let round_trip =
        traffic_policy_document::authoring::http::expand(Some(rendered), &named(), &context)
            .unwrap();
    assert_eq!(round_trip, (http, native));
}

#[test]
fn invalid_ambiguous_and_unbounded_http_declarations_reject_before_runtime() {
    for invalid in [
        CAPTURE.replace("cs.example.test", "http://cs.example.test"),
        CAPTURE.replace("cs.example.test", "*.example.test"),
        CAPTURE.replace("GET", "bad method"),
        CAPTURE.replace("/*", "/prefix*"),
        CAPTURE.replace("/*", "/*?token=x"),
        CAPTURE.replace("    method:", "    unknown: true\n    method:"),
        CAPTURE.replace(
            "    json_urls:",
            "    api: GET /api/sandboxes\n    json_urls:",
        ),
        CAPTURE.replace("[/base_url]", "[]"),
        CAPTURE.replace("[/base_url]", "[/base_url, /base_url]"),
        CAPTURE.replace("[/base_url]", "[not-a-pointer]"),
        CAPTURE.replace(
            "json_urls: [/base_url]",
            "json_urls: [/base_url]\n    typo: true",
        ),
        CAPTURE.replace(
            "json_urls: [/base_url]",
            "json_urls: [/base_url]\n    status_codes: [99]",
        ),
        CAPTURE.replace(
            "json_urls: [/base_url]",
            "json_urls: [/base_url]\n    content_types: [application/json, Application/JSON]",
        ),
        CAPTURE.replace("    json_urls: [/base_url]", "    name: invalid-only"),
        CAPTURE.replace("response_rewrite:", "requests:"),
        CAPTURE.replace("    json_urls:", "    name: ''\n    json_urls:"),
        PATHS.replace(
            "    path_identity:",
            "    response: {capture_urls: [/url]}\n    path_identity:",
        ),
        PATHS.replace(":9100", ""),
        PATHS.replace("segment: 2", "segment: 0"),
        PATHS.replace("segment: 2", "segment: 64"),
        PATHS.replace("{hex: 12}", "{hex: 0}"),
        PATHS.replace("{hex: 12}", "{hex: 12, unknown: true}"),
        PATHS.replace("{hex: 12}", "{hex: 12}\n        nonce: {hex: 10}"),
        PATHS.replace("'%Y%m%d%H%M%S'", "'%Y-%m-%d'"),
        PATHS.replace("user_id: exact", "user_id: arbitrary"),
        PATHS.replace("[storage, task_mysql]", "[]"),
        PATHS.replace("[storage, task_mysql]", "[storage, unknown]"),
        PATHS.replace("[storage, task_mysql]", "[task_mysql]"),
        PATHS.replace(
            "[storage, task_mysql]",
            "[storage, {protocol: http, endpoint: 'storage.example.test:9100'}]",
        ),
    ] {
        assert!(parsed(&invalid).is_err(), "accepted {invalid}");
    }
    let mut duplicated = CAPTURE.to_owned();
    duplicated.push_str(CAPTURE.strip_prefix("response_rewrite:\n").unwrap());
    assert!(parsed(&duplicated).is_err());
    let too_many = format!(
        "response_rewrite:\n{}",
        CAPTURE
            .strip_prefix("response_rewrite:\n")
            .unwrap()
            .repeat(4097)
    );
    assert!(parsed(&too_many).is_err());
}

#[test]
fn mixed_capture_plugins_and_compact_declarations_keep_authored_precedence() {
    let (_, first) = parsed(CAPTURE).unwrap();
    let (_, second) = parsed(&CAPTURE.replace("/base_url", "/other_url")).unwrap();
    let mut legacy = first[0].clone();
    legacy.id = "legacy-url-rule".into();
    let mut plugin = first[0].clone();
    plugin.id = "capture-plugin".into();
    let NativeEffect::CaptureHttpResponse(effect) = &mut plugin.effect else {
        panic!("capture owner");
    };
    effect.contract = CaptureResponseContract::Kubeconfig {
        kubectl_binary: "kubectl".into(),
        proxy_listen: "127.0.0.1:8001".parse().unwrap(),
    };
    for (rules, compact_count) in [
        (vec![first[0].clone(), plugin.clone(), second[0].clone()], 1),
        (vec![plugin.clone(), first[0].clone(), second[0].clone()], 1),
        (vec![first[0].clone(), legacy, plugin, second[0].clone()], 1),
        // Both compact forms select the same physical position. The earlier
        // rule remains native rather than rendering duplicate authored slots.
        (vec![first[0].clone(), second[0].clone()], 1),
    ] {
        let expected = rules.iter().map(|rule| rule.id.clone()).collect::<Vec<_>>();
        let document = crate::policy::TrafficPolicy {
            rules: rules.into_iter().map(Into::into).collect(),
            ..Default::default()
        };
        let before = crate::policy::compile_policy(&document).unwrap();
        let rendered = crate::policy::render_policy(&document).unwrap();
        let after = crate::policy::parse_and_compile_policy(&rendered).unwrap();
        assert_eq!(before.fingerprints, after.fingerprints);
        assert_eq!(
            after
                .native
                .iter()
                .map(|rule| rule.rule.id.clone())
                .collect::<Vec<_>>(),
            expected
        );
        let value: Value = serde_yaml::from_str(&rendered).unwrap();
        assert_eq!(
            value["http"]["response_rewrite"]
                .as_sequence()
                .unwrap()
                .len(),
            compact_count
        );
    }
}

#[test]
fn independent_compact_captures_retain_list_order_and_capture_fingerprint() {
    let (_, first) = parsed(CAPTURE).unwrap();
    let (_, second) = parsed(&CAPTURE.replace("/executor-manager/", "/other-manager/")).unwrap();
    let document = crate::policy::TrafficPolicy {
        rules: vec![first[0].clone().into(), second[0].clone().into()],
        ..Default::default()
    };
    let before = crate::policy::compile_policy(&document).unwrap();
    let output = crate::policy::render_policy(&document).unwrap();
    let parsed = crate::policy::parse_policy(&output).unwrap();
    assert_eq!(parsed.rules[0].id(), first[0].id);
    assert_eq!(parsed.rules[1].id(), second[0].id);
    let after = crate::policy::compile_policy(&parsed).unwrap();
    assert_eq!(before.fingerprints, after.fingerprints);
    let mut swapped = parsed;
    swapped.rules.reverse();
    let reordered = crate::policy::compile_policy(&swapped).unwrap();
    assert_ne!(before.fingerprints.capture, reordered.fingerprints.capture);
    assert_eq!(before.fingerprints.runtime, reordered.fingerprints.runtime);
}

#[test]
fn existing_url_capture_keeps_its_recorder_name_and_capture_fingerprint() {
    let (_, mut rules) = parsed(CAPTURE).unwrap();
    rules[0].id = "cs.example.test".into();
    let document = crate::policy::TrafficPolicy {
        rules: rules.into_iter().map(Into::into).collect(),
        ..Default::default()
    };
    let before = crate::policy::compile_policy(&document).unwrap();
    let output = crate::policy::render_policy(&document).unwrap();
    let value: Value = serde_yaml::from_str(&output).unwrap();
    assert_eq!(
        value["http"]["response_rewrite"][0]["name"],
        "cs.example.test"
    );
    assert!(value.get("rules").is_none());
    let after = crate::policy::parse_and_compile_policy(&output).unwrap();
    assert_eq!(before.fingerprints, after.fingerprints);
    assert_eq!(after.native[0].rule.id, "cs.example.test");
}
