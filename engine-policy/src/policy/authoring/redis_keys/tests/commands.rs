use super::{json, policy};
use crate::policy::parse_policy;

#[test]
fn command_formats_do_not_accept_implicit_permissions_or_authored_relationships() {
    for entry in [
        json!({"key_format":{"kind":"identity","formats":["uuid_v4"]}}),
        json!({"commands":[]}),
        json!({"commands":["SET"]}),
        json!({"commands":[{"operation":"ZADD","arguments":{"1":{"kind":"time","formats":["unix_seconds"],"clock_group":"business"}}}]}),
        json!({"commands":[{"operation":"SET","arguments":{"1":{"kind":"identity","formats":["uuid"]}}}]}),
        json!({"commands":[{"operation":"EVALSHA","arguments":{"13":{"kind":"time","formats":["unix_seconds"]}}}]}),
    ] {
        assert!(
            parse_policy(&policy(json!({"key:*":entry.clone()})).to_string()).is_err(),
            "accepted {entry}"
        );
    }
}
