use super::*;
use crate::replay::policy::feedback::tests::RetiredFixture;
use serde_json::json;
#[test]
fn retired_dependency_response_plan_preserves_current_policy_and_immutable_source() {
    let fixture = RetiredFixture::new();
    fixture.check(||super::super::plan_dependency_request_rule(DependencyRequestRuleFeedback {policy_path:fixture.policy.clone(),replay_report:fixture.evidence.clone(),rule:json!({"id":"lease-expiry","protocol":"mysql","case":{"method":"POST","path":"/lease"},"target":{"host":"db.test","port":3306},"source_evidence":"src/lease.rs stores UTC now plus the lease duration","mysql":{"database":"app","sql":"SELECT expires_at FROM leases WHERE id=? FOR UPDATE","response_time_shift":{"expires_at":{"time":"preserve_relative","format":"mysql_datetime"}}}})}));
}
