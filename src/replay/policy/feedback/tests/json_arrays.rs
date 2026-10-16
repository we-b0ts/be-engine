use super::*;
#[test]
fn retired_array_and_time_modes_cannot_bypass_the_unified_transaction() {
    for kind in [
        ResponseRuleKind::Timestamp,
        ResponseRuleKind::Duration,
        ResponseRuleKind::Unordered,
    ] {
        let fixture = RetiredFixture::new();
        let mut feedback = fixture.response(kind);
        feedback.json_pointers = vec!["/items/*/value".into()];
        if kind == ResponseRuleKind::Timestamp {
            feedback.time = Some(crate::ResponseTimeRule::Timestamp {
                format: crate::ResponseTimestampFormat::Rfc3339,
                mode: crate::ResponseTimestampMode::PreserveRelative,
            });
        }
        fixture.check(|| plan_response_rule(feedback));
    }
}
