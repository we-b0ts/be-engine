//! Exercise one caller-selected real key lifetime; never rewrite its recording.
use super::*;
use crate::replay::redis::append::tests::state_with_policy;
use serde_json::{Value, json};

#[test]
#[ignore = "requires TRAFFIC_E2E_CLOSED_EXPIRY_CASE and TRAFFIC_E2E_CLOSED_EXPIRY_KEY"]
fn recorded_marker_closes_initial_expiry_without_source_refresh_calls() {
    let dir = std::path::PathBuf::from(std::env::var_os("TRAFFIC_E2E_CLOSED_EXPIRY_CASE").unwrap());
    let key = std::env::var("TRAFFIC_E2E_CLOSED_EXPIRY_KEY").unwrap();
    let path = dir.join("dependencies.jsonl");
    let original = std::fs::read(&path).unwrap();
    let events = original
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice::<Value>(l).unwrap())
        .filter(|e| e["event_type"] == "redis_exchange")
        .collect::<Vec<_>>();
    let policy = json!({"format":"traffic-policy/v3",
        "redis":{"keys":{&key:{"kind":"identity","formats":["string"],"read_back":true,"expiry_refresh":true}}}});
    // First prove against the complete unedited Case, including other keys/scripts.
    let (_complete, mut complete) = state_with_policy(&events, policy.clone());
    complete.prepare_observations("case").unwrap();
    let proven = complete
        .observations
        .profiles
        .iter()
        .find(|p| p.kind == Kind::Expiry && p.key == key.as_bytes())
        .unwrap();
    assert_eq!(proven.closed_expiry.len(), 1);
    // Then exercise that key's native calls in a fixture. Unexecuted unrelated
    // key lanes are not waived or reported as a passing full Case.
    let trace = events
        .into_iter()
        .filter(|e| {
            let args = e["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| crate::api_trigger::decode(v).unwrap())
                .collect::<Vec<_>>();
            crate::replay::redis::key_access::touches(
                e["command"].as_str().unwrap(),
                &args,
                key.as_bytes(),
            )
        })
        .collect::<Vec<_>>();
    let (_temp, mut state) = state_with_policy(&trace, policy);
    state.prepare_observations("case").unwrap();
    let profile = state
        .observations
        .profiles
        .iter()
        .find(|p| p.kind == Kind::Expiry && p.key == key.as_bytes())
        .unwrap();
    assert_eq!(profile.closed_expiry.len(), 1);
    let creation = profile.closed_expiry[0].creation;
    let deletion = profile.closed_expiry[0].deletion;
    let refreshes = profile.epochs[profile.closed_expiry[0].epoch]
        .observations
        .clone();
    let target = profile.target.clone();
    let database = profile.database;
    let username = profile.username.clone();
    let version = profile.resp_version;
    let ttl = profile.closed_expiry[0].ttl.as_secs().to_string();
    let trace = state
        .exchanges
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            (e.args.first().is_some_and(|k| k == key.as_bytes())
                && i <= deletion
                && e.record.command != "EXPIRE")
                .then_some((i, e.record.command.clone(), e.args.clone()))
        })
        .collect::<Vec<_>>();
    let mut observed = false;
    for (i, command, args) in trace {
        if i > creation && command == "GET" {
            if observed {
                continue;
            }
            observed = true;
        }
        let matched = state
            .match_redis(
                Some("case"),
                &target,
                TargetConnection::default(),
                version,
                database,
                username.as_deref(),
                &command,
                &args,
            )
            .unwrap();
        state.complete_exchange(&matched);
        if i == creation && refreshes.is_empty() {
            let refresh = state
                .match_redis(
                    Some("case"),
                    &target,
                    TargetConnection::default(),
                    version,
                    database,
                    username.as_deref(),
                    "EXPIRE",
                    &[key.as_bytes().to_vec(), ttl.as_bytes().to_vec()],
                )
                .unwrap();
            assert_eq!(refresh.response, b":1\r\n");
            state.complete_exchange(&refresh);
        }
    }
    assert!(
        refreshes
            .iter()
            .all(|&i| state.exchanges[i].status.is_consumed())
    );
    let audit = state
        .observations
        .audits
        .iter()
        .find(|a| a.coverage.is_some())
        .unwrap();
    assert_eq!(audit.covered_source_observations, refreshes.len());
    assert_eq!(
        audit.source_witness.command,
        if refreshes.is_empty() {
            "SET"
        } else {
            "EXPIRE"
        }
    );
    eprintln!(
        "Recorded scalar lifetime: {} Source refreshes covered by delivered initial TTL and deletion; other Case dependencies remain outside this targeted exercise",
        refreshes.len()
    );
    assert_eq!(std::fs::read(path).unwrap(), original);
}
