use super::*;
use serde_json::json;

fn exchange(sequence: u64, sql: &str, before: u16, after: u16) -> ReplayExchange {
    ReplayExchange {
        source: ReplaySource::Case,
        case_id: Some("case".into()),
        identity: MysqlDependencyIdentity {
            target: TargetKey {
                host: "db.internal".into(),
                port: 3306,
            },
            database: Some("app".into()),
            username: Some("user".into()),
        },
        record: serde_json::from_value(json!({
            "connection_id":Uuid::nil(), "query_sequence":sequence,
            "server_status_before":before, "command":"COM_QUERY", "sql":sql,
            "response":{"status":"ok", "server_status":after,
                "affected_rows":0, "last_insert_id":0}
        }))
        .unwrap(),
        optional_session: None,
        status: ReplayExchangeStatus::Available,
        timing: ReplayExchangeTiming::from_recorded(0, crate::DependencyExchangeOutcome::Response),
    }
}

fn identity() -> ReplaySessionIdentity {
    ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.internal".into(),
            port: 3306,
        }),
        database: Some(" APP ".into()),
        username: Some("USER".into()),
    }
}

fn records(end: &str) -> Vec<ReplayExchange> {
    let mut cleanup = exchange(1, end, 2, 2);
    cleanup.record.connection_id = Some(Uuid::from_u128(1));
    cleanup.optional_session = Some(if end == "commit" {
        OptionalSessionExchange::Commit
    } else {
        OptionalSessionExchange::Rollback
    });
    let mut member = exchange(11, "UPDATE items SET active=0 WHERE id=7", 3, 3);
    member.status = ReplayExchangeStatus::Consumed;
    vec![cleanup, member, exchange(12, end, 3, 2)]
}

// The prior scan is an independent behavior oracle for the indexed selector.
fn reference(
    exchanges: &[ReplayExchange],
    case: Option<&str>,
    identity: &ReplaySessionIdentity,
    command: &str,
    sql: &str,
) -> Option<usize> {
    if command != "COM_QUERY" || !matches!(sql, "commit" | "rollback") {
        return None;
    }
    let in_scope = |exchange: &ReplayExchange| {
        exchange.source == ReplaySource::Case
            && active_case_matches(case, exchange)
            && identity_matches_exchange(identity, &exchange.identity)
    };
    let matches_end = |exchange: &ReplayExchange| {
        exchange.status.is_available()
            && exchange.record.command == command
            && exchange
                .record
                .sql
                .as_deref()
                .is_some_and(|recorded| normalize_sql(recorded) == sql)
            && in_scope(exchange)
    };
    if !exchanges
        .iter()
        .any(|exchange| exchange.optional_session.is_some() && matches_end(exchange))
    {
        return None;
    }
    let completed: HashMap<_, _> = exchanges
        .iter()
        .filter(|exchange| exchange.status.is_consumed() && in_scope(exchange))
        .filter_map(|exchange| {
            Some((
                (
                    exchange.record.connection_id?,
                    exchange.record.query_sequence?,
                ),
                exchange,
            ))
        })
        .collect();
    exchanges.iter().enumerate().find_map(|(index, exchange)| {
        if exchange.optional_session.is_some() || !matches_end(exchange) {
            return None;
        }
        let record = &exchange.record;
        let before = record.server_status_before?;
        if before & 0x2009 != 1 {
            return None;
        }
        let previous = completed.get(&(
            record.connection_id?,
            record.query_sequence?.checked_sub(1)?,
        ))?;
        (previous.identity == exchange.identity
            && previous
                .record
                .response
                .server_status
                .is_some_and(|after| after & 0x200b == before & 0x200b))
        .then_some(index)
    })
}

fn check(index: &mut Index, exchanges: &[ReplayExchange], end: &str, expected: Option<usize>) {
    let actual = index.preferred_end(exchanges, Some("case"), &identity(), "COM_QUERY", Some(end));
    assert_eq!(actual, expected);
    assert_eq!(
        actual,
        reference(exchanges, Some("case"), &identity(), "COM_QUERY", end)
    );
}

#[test]
fn live_delivery_states_preserve_business_end_precedence() {
    let states = [
        ReplayExchangeStatus::Available,
        ReplayExchangeStatus::Responding,
        ReplayExchangeStatus::AwaitingClientTermination,
        ReplayExchangeStatus::Consumed,
        ReplayExchangeStatus::Failed,
    ];
    for end in ["commit", "rollback"] {
        let mut exchanges = records(end);
        let mut index = Index::default();
        index.register(&exchanges);
        for cleanup in states {
            for member in states {
                for business in states {
                    exchanges[0].status = cleanup;
                    exchanges[1].status = member;
                    exchanges[2].status = business;
                    let expected =
                        (cleanup.is_available() && member.is_consumed() && business.is_available())
                            .then_some(2);
                    check(&mut index, &exchanges, end, expected);
                }
            }
        }
    }
}

#[test]
fn scope_identity_sequence_and_protocol_remain_constraints() {
    for end in ["commit", "rollback"] {
        for changed in 0..16 {
            let mut exchanges = records(end);
            match changed {
                0 => exchanges[0].case_id = Some("other".into()),
                1 => exchanges[1].case_id = Some("other".into()),
                2 => exchanges[1].source = ReplaySource::Global,
                3 => exchanges[1].identity.target.host = "other.internal".into(),
                4 => exchanges[1].identity.database = Some("other".into()),
                5 => exchanges[1].identity.username = Some("other".into()),
                6 => exchanges[1].identity.database = Some("APP".into()),
                7 => exchanges[2].record.query_sequence = Some(13),
                8 => exchanges[2].record.connection_id = None,
                9 => exchanges[2].record.server_status_before = None,
                10 => exchanges[2].record.server_status_before = Some(0x2001),
                11 => exchanges[1].record.response.server_status = Some(1),
                12 => exchanges[2].record.command = "COM_STMT_EXECUTE".into(),
                13 => exchanges[2].record.sql = Some(format!("{end} AND CHAIN")),
                14 => exchanges[0].source = ReplaySource::Global,
                15 => exchanges[2].source = ReplaySource::Global,
                _ => unreachable!(),
            }
            check(&mut Index::default(), &exchanges, end, None);
        }
        let mut exchanges = records(end);
        exchanges[2].record.sql = Some(format!(" /* driver */ {} ; ", end.to_uppercase()));
        check(&mut Index::default(), &exchanges, end, Some(2));
        let mut index = Index::default();
        assert_eq!(
            index.preferred_end(
                &exchanges,
                Some("case"),
                &identity(),
                "COM_STMT_EXECUTE",
                Some(end)
            ),
            None
        );
        assert_eq!(
            index.preferred_end(
                &exchanges,
                Some("case"),
                &identity(),
                "COM_QUERY",
                Some("select 1")
            ),
            None
        );
        let mut missing_target = identity();
        missing_target.target = None;
        assert_eq!(
            index.preferred_end(
                &exchanges,
                Some("case"),
                &missing_target,
                "COM_QUERY",
                Some(end)
            ),
            None
        );
    }
}

#[test]
fn optional_classification_changes_are_checked_after_registration() {
    for end in ["commit", "rollback"] {
        let mut exchanges = records(end);
        let mut index = Index::default();
        check(&mut index, &exchanges, end, Some(2));
        let optional = exchanges[0].optional_session.take();
        check(&mut index, &exchanges, end, None);
        exchanges[0].optional_session = optional;
        exchanges[2].optional_session = optional;
        check(&mut index, &exchanges, end, None);
        exchanges[2].optional_session = None;
        check(&mut index, &exchanges, end, Some(2));
    }
}

#[test]
fn last_consumed_duplicate_predecessor_preserves_exact_identity_and_status() {
    for end in ["commit", "rollback"] {
        let mut exchanges = records(end);
        let mut duplicate = exchanges[1].clone();
        duplicate.record.response.server_status = Some(2);
        exchanges.push(duplicate);
        let mut index = Index::default();
        check(&mut index, &exchanges, end, None);
        exchanges[3].status = ReplayExchangeStatus::Failed;
        check(&mut index, &exchanges, end, Some(2));
        exchanges[3].status = ReplayExchangeStatus::Consumed;
        exchanges[3].record.response.server_status = Some(3);
        exchanges[3].identity.database = Some("APP".into());
        check(&mut index, &exchanges, end, None);
        exchanges[3].status = ReplayExchangeStatus::Available;
        check(&mut index, &exchanges, end, Some(2));
    }
}

#[test]
fn late_predecessors_and_inventory_replacement_rebuild_without_stale_candidates() {
    for end in ["commit", "rollback"] {
        let mut exchanges = records(end);
        let predecessor = exchanges.remove(1);
        let mut index = Index::default();
        check(&mut index, &exchanges, end, None);
        exchanges.push(predecessor);
        check(&mut index, &exchanges, end, Some(1));
        exchanges.truncate(1);
        check(&mut index, &exchanges, end, None);
        exchanges = records(end);
        check(&mut index, &exchanges, end, Some(2));
        for exchange in &mut exchanges {
            exchange.case_id = None;
        }
        index = Index::default();
        assert_eq!(
            index.preferred_end(&exchanges, None, &identity(), "COM_QUERY", Some(end)),
            Some(2)
        );
        assert_eq!(
            index.preferred_end(
                &exchanges,
                Some("case"),
                &identity(),
                "COM_QUERY",
                Some(end)
            ),
            None
        );
    }
}

#[test]
#[ignore = "manual scoped end-selection benchmark; run with --ignored --nocapture"]
fn indexed_cleanup_selection_ignores_unrelated_inventory_size() {
    use std::{hint::black_box, time::Instant};

    for unrelated in [0, 1024, 16384] {
        let mut exchanges = records("commit");
        for i in 0..unrelated {
            let mut other = exchange(100 + i as u64, "COMMIT", 2, 2);
            other.case_id = Some(format!("other-{i}"));
            other.optional_session = Some(OptionalSessionExchange::Commit);
            exchanges.push(other);
        }
        let mut index = Index::default();
        index.register(&exchanges);
        let request_identity = identity();
        let started = Instant::now();
        for _ in 0..200 {
            assert_eq!(
                black_box(index.preferred_end(
                    &exchanges,
                    Some("case"),
                    &request_identity,
                    "COM_QUERY",
                    Some("commit")
                )),
                Some(2)
            );
        }
        let indexed_us = started.elapsed().as_micros();
        let started = Instant::now();
        for _ in 0..200 {
            assert_eq!(
                black_box(reference(
                    &exchanges,
                    Some("case"),
                    &request_identity,
                    "COM_QUERY",
                    "commit"
                )),
                Some(2)
            );
        }
        eprintln!(
            "cleanup_selection unrelated={unrelated} iterations=200 indexed_us={indexed_us} scan_us={}",
            started.elapsed().as_micros()
        );
    }
}
