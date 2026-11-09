use super::*;

fn http(scope: ScopePartition, path: Option<&str>) -> HttpKey {
    HttpKey {
        scope,
        secure: false,
        host: "api.test".into(),
        port: 80,
        method: "POST".into(),
        path: path.map(str::to_owned),
    }
}

fn redis(scope: ScopePartition, command: &str) -> RedisKey {
    RedisKey {
        scope,
        host: "cache.test".into(),
        port: 6379,
        resp_version: 2,
        database: 0,
        username: None,
        command: command.into(),
    }
}

#[test]
fn native_http_scope_candidates_match_the_original_ordered_scan_with_shared_aliases() {
    let mut index = ProtocolIndex::http();
    let rows = (0..500)
        .map(|position| {
            let scope = if position % 4 == 0 {
                ScopePartition::Run
            } else {
                ScopePartition::Case(Some(format!("case-{}", position % 5)))
            };
            let path = if position % 3 == 0 {
                "/wanted"
            } else {
                "/other"
            };
            let shared = !matches!(scope, ScopePartition::Run) && position % 7 == 0;
            (scope, path, shared)
        })
        .collect::<Vec<_>>();
    for (position, (scope, path, shared)) in rows.iter().enumerate() {
        index.register(NativeKey::Http(http(scope.clone(), Some(path))), position);
        if *shared {
            index.register(
                NativeKey::Http(http(ScopePartition::Shared, Some(path))),
                position,
            );
        }
    }
    index.seal();
    for scope in [
        ScopePartition::Run,
        ScopePartition::Case(Some("case-1".into())),
        ScopePartition::Case(Some("missing".into())),
    ] {
        let expected = rows
            .iter()
            .enumerate()
            .filter(|(_, (owner, path, shared))| *path == "/wanted" && (*owner == scope || *shared))
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        let actual = index
            .lookup(NativeQuery::Http(&http(scope, Some("/wanted"))))
            .merge(index.lookup(NativeQuery::Http(&http(
                ScopePartition::Shared,
                Some("/wanted"),
            ))))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
}

#[test]
fn redis_subscription_aliases_join_only_run_queries_and_keep_source_order() {
    let mut index = ProtocolIndex::redis();
    let case = ScopePartition::Case(Some("origin".into()));
    for (position, scope, alias) in [
        (0, ScopePartition::Run, false),
        (1, case.clone(), true),
        (2, ScopePartition::Run, false),
        (3, ScopePartition::Case(Some("other".into())), false),
    ] {
        index.register(NativeKey::Redis(redis(scope, "GET")), position);
        if alias {
            index.register(
                NativeKey::Redis(redis(ScopePartition::Shared, "GET")),
                position,
            );
        }
    }
    index.seal();
    assert_eq!(
        index
            .lookup(NativeQuery::Redis(&redis(ScopePartition::Run, "GET")))
            .merge(index.lookup(NativeQuery::Redis(&redis(ScopePartition::Shared, "GET"))))
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(
        index
            .lookup(NativeQuery::Redis(&redis(case, "GET")))
            .collect::<Vec<_>>(),
        [1]
    );
}

#[test]
fn unrelated_cases_do_not_enter_strict_or_hypothesis_candidate_walks() {
    let mut index = ProtocolIndex::redis();
    for position in 0..20_000 {
        index.register(
            NativeKey::Redis(redis(
                ScopePartition::Case(Some(format!("unrelated-{position}"))),
                "SET",
            )),
            position,
        );
    }
    let key = redis(ScopePartition::Case(Some("active".into())), "SET");
    for position in [20_000, 20_001] {
        index.register(NativeKey::Redis(key.clone()), position);
    }
    index.seal();
    for _strict_or_hypothesis in [false, true] {
        let mut visited = 0;
        let candidates = index
            .lookup(NativeQuery::Redis(&key))
            .inspect(|_| visited += 1)
            .collect::<Vec<_>>();
        assert_eq!(visited, 2);
        assert_eq!(candidates, [20_000, 20_001]);
    }
}

#[test]
fn a_legal_time_rule_candidate_stays_ahead_of_a_later_exact_payload() {
    use crate::policy::{FieldContract, TimeAnchor, TimeRelation, TimestampFormat};
    use crate::value_contract::json::{AnchorClocks, Field, compare};
    use crate::value_contract::time::ClockPair;
    use serde_json::json;

    let contract = FieldContract::Time {
        format: TimestampFormat::UnixSeconds,
        relation: TimeRelation::PreserveOffset,
        anchor: TimeAnchor::DependencyRequestStart,
        utc_offset: None,
        clock_group: None,
        clock_scope: Default::default(),
    };
    let fields = [Field {
        rule_id: "request-clock",
        pointer: "/at",
        contract: &contract,
    }];
    let clocks = AnchorClocks {
        dependency: ClockPair {
            source: chrono::DateTime::from_timestamp(10, 0),
            target: chrono::DateTime::from_timestamp(110, 0),
        },
        ..Default::default()
    };
    let source = [json!({"at":10,"value":7}), json!({"at":110,"value":7})];
    let target = json!({"at":110,"value":7});
    let key = http(ScopePartition::Case(Some("active".into())), Some("/clock"));
    let mut index = ProtocolIndex::http();
    for position in 0..2 {
        index.register(NativeKey::Http(key.clone()), position);
    }
    index.seal();
    let selected = index.lookup(NativeQuery::Http(&key)).find(|position| {
        source[*position] == target
            || compare(&source[*position], &target, &fields, clocks).passed()
    });
    assert_eq!(selected, Some(0));
    assert_ne!(source[0], target);
    assert_eq!(source[1], target);
}

#[test]
fn coarse_http_candidates_preserve_generated_paths_without_broadening_exact_lookup() {
    let scope = ScopePartition::Case(Some("active".into()));
    let mut index = ProtocolIndex::http();
    for (position, path) in ["/x/source-id", "/unrelated"].into_iter().enumerate() {
        index.register(NativeKey::Http(http(scope.clone(), Some(path))), position);
        index.register(NativeKey::Http(http(scope.clone(), None)), position);
    }
    index.seal();
    assert!(
        index
            .lookup(NativeQuery::Http(&http(
                scope.clone(),
                Some("/x/target-id")
            )))
            .next()
            .is_none()
    );
    assert_eq!(
        index
            .lookup(NativeQuery::Http(&http(
                scope.clone(),
                Some("/x/source-id")
            )))
            .collect::<Vec<_>>(),
        [0]
    );
    assert_eq!(
        index
            .lookup(NativeQuery::Http(&http(scope, None)))
            .collect::<Vec<_>>(),
        [0, 1]
    );
}

#[test]
fn lane_blockers_cross_command_buckets_but_not_case_or_actual_owner_boundaries() {
    let connection = uuid::Uuid::new_v4();
    let mut lanes = LaneIndex::default();
    let lane = LaneKey {
        owner: LaneOwner::Case,
        case: Some("active".into()),
        connection,
    };
    for (position, sequence) in [(1, 2), (4, 3), (5, 4)] {
        lanes.register(lane.clone(), sequence, position);
    }
    // Both unrelated physical owners and an older Case share the socket UUID.
    for (position, owner, case) in [
        (0, LaneOwner::Startup, None),
        (2, LaneOwner::Process, None),
        (3, LaneOwner::Case, Some("earlier".into())),
    ] {
        lanes.register(
            LaneKey {
                owner,
                case,
                connection,
            },
            1,
            position,
        );
    }
    // Slot 1 may be SET while the selected slot is GET: commands are not lanes.
    assert_eq!(lanes.blocker(5, |_| true), Some(1));
    assert_eq!(lanes.blocker(5, |position| position != 1), Some(4));
    assert_eq!(lanes.blocker(5, |_| false), None);
}

#[test]
fn incremental_preparation_keeps_existing_cursor_and_unchanged_bucket_storage() {
    let mut index = ProtocolIndex::http();
    let first = http(ScopePartition::Case(Some("first".into())), Some("/x"));
    index.register(NativeKey::Http(first.clone()), 0);
    index.seal();
    let prior = index.lookup(NativeQuery::Http(&first)).into_indices();
    let second = http(ScopePartition::Case(Some("second".into())), Some("/x"));
    index.register(NativeKey::Http(second), 1);
    index.seal();
    assert!(Arc::ptr_eq(
        &prior,
        &index.lookup(NativeQuery::Http(&first)).into_indices()
    ));
    index.register(NativeKey::Http(first.clone()), 2);
    index.seal();
    assert_eq!(prior.as_ref(), [0]);
    assert_eq!(
        index.lookup(NativeQuery::Http(&first)).collect::<Vec<_>>(),
        [0, 2]
    );
}

#[test]
fn mysql_command_postings_match_query_execute_compatibility_without_reordering() {
    let commands = [
        "COM_QUERY",
        "COM_PING",
        "COM_STMT_EXECUTE",
        "sql",
        "COM_QUERY",
    ];
    let mut index = ProtocolIndex::mysql();
    let key = |command| MysqlKey {
        scope: ScopePartition::Case(Some("active".into())),
        host: "sql.test".into(),
        port: 3306,
        database: Some("app".into()),
        username: Some("user".into()),
        command: MysqlCommand::new(command),
    };
    for (position, command) in commands.iter().enumerate() {
        index.register(NativeKey::Mysql(key(None)), position);
        index.register(NativeKey::Mysql(key(Some(command))), position);
    }
    index.seal();
    for query in [
        None,
        Some("COM_QUERY"),
        Some("COM_STMT_EXECUTE"),
        Some("COM_PING"),
        Some("sql"),
    ] {
        let scanned = commands
            .iter()
            .enumerate()
            .filter(|(_, recorded)| {
                query.is_none_or(|query| {
                    query == **recorded
                        || [query, **recorded]
                            .into_iter()
                            .all(|c| matches!(c, "COM_QUERY" | "COM_STMT_EXECUTE"))
                })
            })
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        assert_eq!(
            index
                .lookup(NativeQuery::Mysql(&key(query)))
                .collect::<Vec<_>>(),
            scanned
        );
    }
}

#[test]
fn optional_mysql_sequences_keep_the_original_predecessor_comparison() {
    let mut index = LaneIndex::default();
    let lane = LaneKey {
        owner: LaneOwner::Case,
        case: Some("active".into()),
        connection: uuid::Uuid::new_v4(),
    };
    index.register_optional(lane.clone(), None, 0);
    index.register_optional(lane, Some(2), 1);
    assert_eq!(index.blocker(1, |_| true), Some(0));
    assert_eq!(index.blocker(0, |_| true), None);
}

#[test]
fn blocker_existence_scans_each_lane_once_per_selection() {
    use std::cell::Cell;

    let mut index = LaneIndex::default();
    let lane = LaneKey {
        owner: LaneOwner::Case,
        case: Some("active".into()),
        connection: uuid::Uuid::new_v4(),
    };
    index.register(lane.clone(), 10, 0);
    index.register_optional(lane.clone(), None, 1);
    for position in 2..1026 {
        index.register(lane.clone(), position as u64, position);
    }
    let other = LaneKey {
        case: Some("other".into()),
        ..lane
    };
    index.register(other, 20, 1026);
    let inspections = Cell::new(0);
    let mut blocked = index.blocked_candidates(|position| {
        inspections.set(inspections.get() + 1);
        position == 0 || position == 1
    });
    for position in 0..1028 {
        assert_eq!(
            blocked(position),
            index
                .blocker(position, |prior| prior == 0 || prior == 1)
                .is_some()
        );
    }
    assert_eq!(inspections.get(), 1027);
    let mut next = index.blocked_candidates(|position| position == 0);
    assert!(!next(2));
    assert!(next(11));
}
