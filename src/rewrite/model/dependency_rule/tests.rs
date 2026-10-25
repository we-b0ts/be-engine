use super::*;

#[test]
fn every_request_rule_requires_fresh_replay_and_process_rules_do_not() {
    use RewriteDependencyRuleSpec as Spec;
    let request_rules = [
        Spec::HttpCrossCase {
            selector: crate::HttpCrossCaseSelector {
                host: Some("http.test".into()),
                port: Some(80),
                method: "GET".into(),
                path: "/read".into(),
            },
        },
        Spec::RedisCrossCase {
            rule_id: "shift".into(),
        },
        Spec::MysqlSqlTime {
            selector: crate::MysqlTimeSelector {
                target_host: "mysql.test".into(),
                target_port: 3306,
                database: "db".into(),
                username: "user".into(),
                sql: "SELECT ?".into(),
                tables: vec![],
                table_patterns: vec![],
                table_series: None,
                time_values: vec![],
            },
        },
        Spec::MemcachedProtobufTimestamp {
            rule_id: "time".into(),
            port: 11211,
            key_prefix: "cache:".into(),
            key_suffix: "".into(),
            field_number: 1,
        },
    ];
    for rule in request_rules {
        assert!(rule.requires_fresh_replay(), "{rule:?}");
    }
    let process_rules = [
        Spec::Http {
            authority: "http.test".into(),
            method: "GET".into(),
            path_prefix: "/refresh".into(),
        },
        Spec::Motan {
            group: "g".into(),
            interface_name: "i".into(),
            method_name: "read".into(),
        },
        Spec::Memcached {
            breeze_resource: "cache".into(),
            command: "get".into(),
            key_start: 0,
            key_end: 1,
            key_separator: ":".into(),
            key_suffix: "".into(),
            initial_load_timeout_ms: 60000,
        },
        Spec::RedisZcount {
            ports: vec![6379],
            key_prefix: "cache:".into(),
            key_suffix: "".into(),
        },
        Spec::RedisGet {
            ports: vec![6379],
            keys: vec!["key".into()],
            initial_load_timeout_ms: 60000,
        },
        Spec::RedisScard {
            ports: vec![6379],
            keys: vec!["key".into()],
            initial_load_timeout_ms: 60000,
        },
        Spec::RedisHgetall {
            ports: vec![6379],
            keys: vec!["key".into()],
            initial_load_timeout_ms: 60000,
        },
        Spec::RedisHscan {
            ports: vec![6379],
            keys: vec!["key".into()],
            key_patterns: vec![],
        },
        Spec::RedisHashRead {
            command: "HGET".into(),
            ports: vec![6379],
            keys: vec!["key".into()],
            key_patterns: vec![],
            fields: vec!["field".into()],
        },
    ];
    for rule in process_rules {
        assert!(!rule.requires_fresh_replay(), "{rule:?}");
    }
}
