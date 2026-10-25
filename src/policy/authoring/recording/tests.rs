use super::*;
use crate::policy::{self, TrafficPolicy};

const DECLARED: &str = r#"format: traffic-policy/v2
source_revision: source-v1
recording:
  case_paths: [/api/z/*, /api/a/*]
"#;

fn revision(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

fn declared() -> String {
    DECLARED.replace("source-v1", &revision('1'))
}

fn legacy(name: &str) -> String {
    format!(
        "format: traffic-policy/v2\nsource_revision: {}\nrules:\n- id: {name}\n  match: {{}}\n  effect: {{kind: capture_http, case_paths: [/api/z/*, /api/a/*]}}\n",
        revision('1')
    )
}

#[test]
fn recording_scope_preserves_source_revision_path_order_name_and_all_fingerprints() {
    let before = policy::parse_and_compile_policy(&legacy(DEFAULT_NAME)).unwrap();
    let document = policy::parse_policy(&declared()).unwrap();
    let after = policy::compile_policy(&document).unwrap();
    assert_eq!(before.fingerprints, after.fingerprints);
    assert_eq!(after.native[0].rule.id, DEFAULT_NAME);
    let NativeEffect::CaptureHttp(effect) = &after.native[0].rule.effect else {
        panic!("recording acquisition owner");
    };
    assert_eq!(effect.source_revision, revision('1'));
    assert_eq!(effect.case_paths, ["/api/z/*", "/api/a/*"]);
    let rendered = policy::render_policy(&document).unwrap();
    let value: Value = serde_yaml::from_str(&rendered).unwrap();
    assert!(value.get("rules").is_none());
    assert!(value["recording"].get("name").is_none());
    assert_eq!(
        value.as_mapping().unwrap().keys().last().unwrap(),
        "recording"
    );
    assert_eq!(
        rendered,
        policy::render_policy(&policy::parse_policy(&rendered).unwrap()).unwrap()
    );
    let renamed = declared().replace(
        "  case_paths:",
        "  name: custom-recording-scope\n  case_paths:",
    );
    let named = policy::parse_policy(&renamed).unwrap();
    assert_eq!(named.rules[0].id(), "custom-recording-scope");
    assert_eq!(
        policy::compile_policy(&named).unwrap().fingerprints,
        policy::parse_and_compile_policy(&legacy("custom-recording-scope"))
            .unwrap()
            .fingerprints
    );
    assert!(
        policy::render_policy(&named)
            .unwrap()
            .contains("name: custom-recording-scope")
    );
}

#[test]
fn recording_proof_is_source_bound_but_stays_out_of_runtime_and_rule_identity() {
    let explained = declared().replace(
        "recording:\n",
        "recording:\n  proof: {source: 'routes.py:10', fact: Source exposes these HTTP routes}\n",
    );
    let bare = policy::parse_policy(&declared()).unwrap();
    let proposed = policy::parse_policy(&explained).unwrap();
    policy::require_source_proofs(&proposed).unwrap();
    assert_eq!(
        proposed.rules[0].proof().unwrap().source,
        format!("routes.py:10 @ {}", revision('1'))
    );
    assert!(policy::require_source_proofs(&bare).is_err());
    assert_eq!(
        policy::compile_policy(&bare).unwrap().fingerprints,
        policy::compile_policy(&proposed).unwrap().fingerprints
    );
    assert_eq!(
        policy::render_policy(&bare).unwrap(),
        policy::render_policy(&proposed).unwrap()
    );
    let different_revision = DECLARED.replace("source-v1", &revision('2'));
    let before = policy::compile_policy(&bare).unwrap();
    let changed = policy::parse_and_compile_policy(&different_revision).unwrap();
    assert_ne!(before.fingerprints.capture, changed.fingerprints.capture);
    assert_ne!(before.fingerprints.full, changed.fingerprints.full);
    assert_eq!(before.fingerprints.runtime, changed.fingerprints.runtime);
}

#[test]
fn recording_is_rendered_last_after_codecs_http_apis_and_retained_native_rules() {
    let input = format!(
        "{}{}",
        declared(),
        r#"http:
  headers:
    x-observed-at: {kind: time, formats: [rfc3339]}
docx:
  fields:
    - {kind: timestamp, part: docProps/core.xml, element: 'dcterms:created', format: rfc3339}
api:
  GET /api/export:
    response:
      body: {codec: docx}
rules:
  - id: legacy-calendar-header
    match: {api: GET /api/download}
    effect: {kind: response_header_date, header: content-disposition, parameter: filename, format: '%Y-%m-%d'}
"#
    );
    let document = policy::parse_policy(&input).unwrap();
    let output = policy::render_policy(&document).unwrap();
    let recording = output.find("\nrecording:").unwrap();
    for field in ["http", "docx", "api", "rules"] {
        assert!(
            output.find(&format!("\n{field}:")).unwrap() < recording,
            "{output}"
        );
    }
    let value: Value = serde_yaml::from_str(&output).unwrap();
    assert_eq!(value["rules"].as_sequence().unwrap().len(), 1);
    assert_eq!(
        value.as_mapping().unwrap().keys().last().unwrap(),
        "recording"
    );
    assert_eq!(
        policy::compile_policy(&document).unwrap().fingerprints,
        policy::parse_and_compile_policy(&output)
            .unwrap()
            .fingerprints
    );
    assert_eq!(
        output,
        policy::render_policy(&policy::parse_policy(&output).unwrap()).unwrap()
    );
}

#[test]
fn unbound_legacy_scopes_and_multiple_native_owners_keep_lossless_stable_rendering() {
    let unbound = legacy("legacy-scope")
        .replace(&format!("source_revision: {}\n", revision('1')), "")
        .replace(
            "kind: capture_http,",
            &format!("kind: capture_http, source_revision: {},", revision('1')),
        );
    let document = policy::parse_policy(&unbound).unwrap();
    let output = policy::render_policy(&document).unwrap();
    let raw: Value = serde_yaml::from_str(&output).unwrap();
    assert!(raw.get("recording").is_none());
    assert_eq!(raw["rules"].as_sequence().unwrap().len(), 1);
    let mut document = policy::parse_policy(&declared()).unwrap();
    let mut second = document.rules[0].as_native().unwrap().clone();
    second.id = "another-legacy-scope".into();
    let NativeEffect::CaptureHttp(effect) = &mut second.effect else {
        panic!("recording acquisition owner");
    };
    effect.case_paths = vec!["/other/*".into()];
    document.rules.insert(0, second.into());
    let before = policy::compile_policy(&document).unwrap();
    let output = policy::render_policy(&document).unwrap();
    let raw: Value = serde_yaml::from_str(&output).unwrap();
    assert!(raw["recording"].get("name").is_none());
    assert_eq!(raw["rules"][0]["id"], "another-legacy-scope");
    assert_eq!(
        before.fingerprints,
        policy::parse_and_compile_policy(&output)
            .unwrap()
            .fingerprints
    );
    assert_eq!(
        output,
        policy::render_policy(&policy::parse_policy(&output).unwrap()).unwrap()
    );
    let mut constrained = document.rules[0].as_native().unwrap().clone();
    constrained.selector.api = Some("GET /other".into());
    assert!(
        !compact(
            &constrained.into(),
            Some(&revision('1')),
            &mut Mapping::new()
        )
        .unwrap()
    );
}

#[test]
fn recording_rejects_missing_revision_unknown_fields_invalid_paths_and_conflicting_proof() {
    let valid = declared();
    for input in [
        valid.replace(&revision('1'), "snapshot-v1"),
        valid.replace(&revision('1'), &revision('A')),
        valid.replace(&format!("source_revision: {}\n", revision('1')), ""),
        valid.replace("[/api/z/*, /api/a/*]", "[]"),
        valid.replace("/api/z/*", "/api/z-prefix*"),
        valid.replace("  case_paths:", &format!("  source_revision: {}\n  case_paths:", revision('1'))),
        valid.replace("  case_paths:", "  unknown: true\n  case_paths:"),
        valid.replace("  case_paths:", "  name: ''\n  case_paths:"),
        valid.replace("recording:\n", &format!("recording:\n  proof: {{source: 'routes.py @ {}', fact: Source defines these routes}}\n", revision('2'))),
        valid.replace("  case_paths:", "  case_paths: [/duplicate]\n  case_paths:"),
    ] {
        assert!(policy::parse_policy(&input).is_err(), "accepted {input}");
    }
    let declaration = Declaration {
        case_paths: vec!["/api/*".into(); 4097],
        name: default_name(),
        proof: None,
    };
    assert!(expand(Some(declaration), Some(&revision('1'))).is_err());
    assert!(
        !policy::render_policy(&TrafficPolicy::default())
            .unwrap()
            .contains("rules:")
    );
}

#[test]
fn recorder_case_path_bootstrap_reads_and_updates_recording_without_changing_comparison_policy() {
    use crate::config::{
        CasePathPatternAuthority, CasePathPatternFeedback, plan_case_path_pattern_feedback,
    };
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".traffic-e2e");
    std::fs::create_dir(&directory).unwrap();
    let project = directory.join("project.yaml");
    let path = directory.join("policy.yaml");
    let revision = format!("sha256:{}", "a".repeat(64));
    let project_text = "project:\n  policy: .traffic-e2e/policy.yaml\nrecorder:\n  http_gateway:\n    enabled: true\n    rules:\n    - name: api\n      path_prefixes: [/api]\n  recording:\n    access_policy: unrestricted\n";
    std::fs::write(&project, project_text).unwrap();
    let original = format!(
        "{}{}",
        DECLARED.replace("source-v1", &revision),
        "signatures:\n  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: JWT_KEY}}\napi:\n  POST /api/action:\n    request:\n      headers:\n        authorization: {signature: default, scheme: bearer}\n"
    );
    std::fs::write(&path, &original).unwrap();
    let before = policy::parse_and_compile_policy(&original).unwrap();
    let mut feedback = CasePathPatternFeedback {
        project_config_path: project.clone(),
        rules_path: path.clone(),
        source_revision: revision.clone(),
        case_source: "/recordings/source".into(),
        authority: CasePathPatternAuthority::Focused,
        patterns: vec!["/api/new/*".into()],
        incorrect_patterns: vec![],
        correction_evidence: None,
    };
    let plan = plan_case_path_pattern_feedback(feedback.clone()).unwrap();
    assert_eq!(plan.report().added, ["/api/new/*"]);
    plan.apply(false).unwrap();
    let expanded = std::fs::read_to_string(&path).unwrap();
    let raw: Value = serde_yaml::from_str(&expanded).unwrap();
    assert!(raw.get("rules").is_none());
    assert_eq!(
        raw["recording"]["case_paths"],
        serde_yaml::from_str::<Value>("[/api/z/*, /api/a/*, /api/new/*]").unwrap()
    );
    let after_addition = policy::parse_and_compile_policy(&expanded).unwrap();
    assert_ne!(
        before.fingerprints.capture,
        after_addition.fingerprints.capture
    );
    assert_eq!(
        before.fingerprints.runtime,
        after_addition.fingerprints.runtime
    );
    for unchanged in before
        .native
        .iter()
        .filter(|rule| !matches!(rule.rule.effect, NativeEffect::CaptureHttp(_)))
    {
        assert_eq!(
            after_addition
                .native
                .iter()
                .find(|rule| rule.rule.id == unchanged.rule.id),
            Some(unchanged)
        );
    }
    assert!(
        !plan_case_path_pattern_feedback(feedback.clone())
            .unwrap()
            .report()
            .changed
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), expanded);
    feedback.patterns.clear();
    feedback.incorrect_patterns = vec!["/api/z/*".into()];
    feedback.correction_evidence =
        Some("Source inventory contains only the remaining routes".into());
    let plan = plan_case_path_pattern_feedback(feedback.clone()).unwrap();
    assert_eq!(plan.report().removed, ["/api/z/*"]);
    plan.apply(true).unwrap();
    let updated = std::fs::read_to_string(&path).unwrap();
    let raw: Value = serde_yaml::from_str(&updated).unwrap();
    assert!(raw.get("rules").is_none());
    assert_eq!(
        raw["recording"]["case_paths"],
        serde_yaml::from_str::<Value>("[/api/a/*, /api/new/*]").unwrap()
    );
    assert_eq!(
        raw.as_mapping().unwrap().keys().last().unwrap(),
        "recording"
    );
    let after = policy::parse_and_compile_policy(&updated).unwrap();
    assert_eq!(before.fingerprints.runtime, after.fingerprints.runtime);
    assert_eq!(
        before.fingerprints.classification,
        after.fingerprints.classification
    );
    assert_ne!(
        after_addition.fingerprints.capture,
        after.fingerprints.capture
    );
    assert_eq!(std::fs::read_to_string(&project).unwrap(), project_text);
    let mut no_op = feedback;
    no_op.incorrect_patterns.clear();
    no_op.correction_evidence = None;
    no_op.patterns = vec!["/api/a/*".into()];
    assert!(
        !plan_case_path_pattern_feedback(no_op)
            .unwrap()
            .report()
            .changed
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), updated);
}

#[test]
fn empty_policy_bootstrap_binds_explicit_revision_and_converges_on_one_recording_owner() {
    use crate::config::{
        CasePathPatternAuthority, CasePathPatternFeedback, plan_case_path_pattern_feedback,
    };
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".traffic-e2e");
    std::fs::create_dir(&directory).unwrap();
    let project = directory.join("project.yaml");
    let path = directory.join("policy.yaml");
    let project_text = "project:\n  policy: .traffic-e2e/policy.yaml\nrecorder:\n  http_gateway:\n    enabled: true\n    rules:\n    - name: api\n      path_prefixes: [/api]\n  recording:\n    access_policy: unrestricted\n";
    std::fs::write(&project, project_text).unwrap();
    let mut original: Value =
        serde_yaml::from_str(&crate::config::native_policy::empty_policy().unwrap()).unwrap();
    let declarations: Value = serde_yaml::from_str(
        "json:\n  fields:\n    /created_at: {kind: time, formats: [unix_seconds]}\nsignatures:\n  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: JWT_KEY}}\napi:\n  POST /api/action:\n    request:\n      headers:\n        authorization: {signature: default, scheme: bearer}\n"
    ).unwrap();
    original
        .as_mapping_mut()
        .unwrap()
        .extend(declarations.as_mapping().unwrap().clone());
    let original = serde_yaml::to_string(&original).unwrap();
    let before = policy::parse_and_compile_policy(&original).unwrap();
    let initial_json = before.global_json.clone();
    std::fs::write(&path, original).unwrap();
    let revision = format!("sha256:{}", "b".repeat(64));
    let mut feedback = CasePathPatternFeedback {
        project_config_path: project.clone(),
        rules_path: path.clone(),
        source_revision: revision.clone(),
        case_source: "/recordings/initial-source".into(),
        authority: CasePathPatternAuthority::Focused,
        patterns: vec!["/api/z/*".into()],
        incorrect_patterns: vec![],
        correction_evidence: None,
    };
    plan_case_path_pattern_feedback(feedback.clone())
        .unwrap()
        .apply(false)
        .unwrap();
    let first = std::fs::read_to_string(&path).unwrap();
    let raw: Value = serde_yaml::from_str(&first).unwrap();
    assert_eq!(raw["source_revision"], revision);
    assert!(raw.get("rules").is_none());
    assert_eq!(
        raw.as_mapping().unwrap().keys().last().unwrap(),
        "recording"
    );
    assert_eq!(
        raw["recording"]["case_paths"],
        serde_yaml::from_str::<Value>("[/api/z/*]").unwrap()
    );
    let first_compiled = policy::parse_and_compile_policy(&first).unwrap();
    assert_eq!(first_compiled.global_json, initial_json);
    assert_eq!(
        before.fingerprints.runtime,
        first_compiled.fingerprints.runtime
    );
    for unchanged in &before.native {
        assert_eq!(
            first_compiled
                .native
                .iter()
                .find(|rule| rule.rule.id == unchanged.rule.id),
            Some(unchanged)
        );
    }
    assert!(
        first_compiled
            .native
            .iter()
            .any(|rule| rule.rule.id == DEFAULT_NAME)
    );
    assert!(
        !plan_case_path_pattern_feedback(feedback.clone())
            .unwrap()
            .report()
            .changed
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
    feedback.patterns = vec!["/api/a/*".into()];
    plan_case_path_pattern_feedback(feedback.clone())
        .unwrap()
        .apply(false)
        .unwrap();
    let second = std::fs::read_to_string(&path).unwrap();
    let raw: Value = serde_yaml::from_str(&second).unwrap();
    assert_eq!(raw["source_revision"], revision);
    assert!(raw.get("rules").is_none());
    assert_eq!(
        raw["recording"]["case_paths"],
        serde_yaml::from_str::<Value>("[/api/z/*, /api/a/*]").unwrap()
    );
    let second_compiled = policy::parse_and_compile_policy(&second).unwrap();
    assert_eq!(second_compiled.global_json, initial_json);
    assert_eq!(
        before.fingerprints.runtime,
        second_compiled.fingerprints.runtime
    );
    assert_ne!(
        first_compiled.fingerprints.capture,
        second_compiled.fingerprints.capture
    );
    assert_eq!(
        second_compiled
            .native
            .iter()
            .filter(|rule| matches!(rule.rule.effect, NativeEffect::CaptureHttp(_)))
            .count(),
        1
    );
    for unchanged in &before.native {
        assert_eq!(
            second_compiled
                .native
                .iter()
                .find(|rule| rule.rule.id == unchanged.rule.id),
            Some(unchanged)
        );
    }
    assert!(
        !plan_case_path_pattern_feedback(feedback)
            .unwrap()
            .report()
            .changed
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), second);
    assert_eq!(std::fs::read_to_string(project).unwrap(), project_text);
}

#[test]
fn initial_recording_never_overwrites_existing_revision_or_discards_conflicting_source_facts() {
    use crate::config::native_policy::{parse_source_policy, render_updated};
    let proof = Proof {
        source: "routes.py:10".into(),
        fact: "Source defines this recording scope".into(),
    };
    let old = revision('0');
    let new = revision('1');
    let bound = format!("format: traffic-policy/v2\nsource_revision: {old}\n");
    let mut proposal = parse_source_policy(&bound).unwrap();
    proposal.http.source_revision = new.clone();
    proposal.http.case_path_patterns = vec!["/api/*".into()];
    assert!(render_updated(&bound, &proposal, &proof).is_err());
    proposal.http.source_revision = old.clone();
    let result = render_updated(&bound, &proposal, &proof).unwrap();
    let raw: Value = serde_yaml::from_str(&result).unwrap();
    assert_eq!(raw["source_revision"], old);
    assert!(raw.get("rules").is_none());
    assert!(raw.get("recording").is_some());
    let old_effect = r#"format: traffic-policy/v2
rules:
  - id: existing-source-task
    match: {}
    effect:
      kind: process_owned
      source_revision: source-v0
      selector: {protocol: http, authorities: [background.test], methods: [GET], path_prefixes: [/health]}
"#.replace("source-v0", &old);
    let old_proof = r#"format: traffic-policy/v2
signatures:
  default: {kind: jwt, algorithm: HS256, key: {kind: target_env, name: JWT_KEY}}
api:
  POST /api/action:
    request:
      headers:
        authorization:
          signature: default
          scheme: bearer
          proof: {source: 'auth.py:20 @ source-v0', fact: Source verifies this request token}
"#
    .replace("source-v0", &old);
    for original in [&old_effect, &old_proof] {
        let mut proposal = parse_source_policy(original).unwrap();
        proposal.http.source_revision = new.clone();
        proposal.http.case_path_patterns = vec!["/api/*".into()];
        assert!(render_updated(original, &proposal, &proof).is_err());
    }
    let compatible = old_effect.replace(&old, &new);
    let before = policy::parse_and_compile_policy(&compatible).unwrap();
    let mut proposal = parse_source_policy(&compatible).unwrap();
    proposal.http.source_revision = new;
    proposal.http.case_path_patterns = vec!["/api/*".into()];
    let output = render_updated(&compatible, &proposal, &proof).unwrap();
    let after = policy::parse_and_compile_policy(&output).unwrap();
    assert_eq!(
        before.fingerprints.classification,
        after.fingerprints.classification
    );
    assert_eq!(
        after
            .native
            .iter()
            .find(|rule| rule.rule.id == "existing-source-task"),
        Some(&before.native[0])
    );
}
