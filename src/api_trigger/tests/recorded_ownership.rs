//! Opt-in verification of immutable real recording evidence; never used by Target code.
use super::*;

#[test]
#[ignore = "requires TRAFFIC_E2E_TRANSACTION_CASE and TRAFFIC_E2E_TRANSACTION_POLICY"]
fn recorded_624_644_ownership_and_cache_performance() {
    let case = PathBuf::from(std::env::var_os("TRAFFIC_E2E_TRANSACTION_CASE").unwrap());
    let policy = PathBuf::from(std::env::var_os("TRAFFIC_E2E_TRANSACTION_POLICY").unwrap());
    let (policy, _) = SourceTrafficPolicyConfig::load_with_fingerprints(&policy).unwrap();
    let events: Vec<Value> = fs::read_to_string(case.join("dependencies.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let commits: Vec<_> = events.iter().filter(|e| e["sql"] == "COMMIT").collect();
    assert_eq!(commits.len(), 2);
    let case_id = case.file_name().unwrap().to_str().unwrap();
    let started = std::time::Instant::now();
    let first = load(&case, &policy.process_owned_dependencies).unwrap();
    let first_ms = started.elapsed().as_secs_f64() * 1000.;
    let owner = first
        .witness(case_id, commits[0])
        .expect("leading COMMIT must belong to the background transaction");
    assert_eq!(owner.rule, "responses-async-task-failure-update");
    assert_ne!(owner.trigger_case_id, case_id);
    assert!(
        first.witness(case_id, commits[1]).is_none(),
        "business COMMIT must remain required"
    );
    let mut warm_ms = Vec::new();
    for _ in 0..3 {
        let started = std::time::Instant::now();
        let warm = load(&case, &policy.process_owned_dependencies).unwrap();
        warm_ms.push(started.elapsed().as_secs_f64() * 1000.);
        assert!(warm.cache_reused);
        assert_eq!(warm.source_bytes, 0);
        assert!(warm.witness(case_id, commits[0]).is_some());
        assert!(warm.witness(case_id, commits[1]).is_none());
    }
    eprintln!(
        "transaction_ownership_performance: {}",
        json!({"first_ms":first_ms,
        "first_cache_reused":first.cache_reused,"first_payload_bytes":first.source_bytes,
        "warm_ms":warm_ms,"warm_payload_bytes":0,"foreign_commit_exempt":true,"business_commit_required":true})
    );
}
