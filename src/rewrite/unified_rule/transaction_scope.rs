//! Execution selection never truncates a rule's own complete Source scope.
use super::*;

fn extra(fixture: &Fixture, uri: &str) {
    let source = fixture.state().case_source.clone().unwrap();
    let case = source.join("apis/other/case-2");
    fs::create_dir_all(&case).unwrap();
    write(
        &case.join("request.json"),
        json!({"method":"GET","uri":uri}),
    );
    write(
        &case.join("expected-response.json"),
        json!({"status":200,"body":body(json!({}))}),
    );
    fs::write(case.join("dependencies.jsonl"), "").unwrap();
}

#[test]
fn global_formats_reenumerate_unprepared_apis_before_apply() {
    let fixture = Fixture::new();
    extra(&fixture, "/skipped");
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    extra(&fixture, "/newly-added");
    assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
}

#[test]
fn an_omitted_case_of_the_focused_api_still_blocks_planning() {
    let fixture = Fixture::new();
    extra(&fixture, "/api");
    fixture.confirm();
    assert!(fixture.plan().is_err());
    assert!(fixture.state().rule_plan.is_none());
}
