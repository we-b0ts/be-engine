use super::*;

fn resources(value: serde_json::Value) -> Vec<AsyncEnd> {
    serde_json::from_value(value).unwrap()
}

fn observe_both(live: &ResourceScope, recorded: &ResourceScope, event: &RecorderEvent, all: bool) {
    let live_match = live.observe(event).is_some();
    let recorded_match = recorded
        .observe_recorded(&serde_json::to_value(event).unwrap())
        .unwrap()
        .is_some();
    assert_eq!(live_match, recorded_match);
    assert_eq!(live.all_ends_matched(), all);
    assert_eq!(recorded.all_ends_matched(), all);
}

#[test]
fn one_exchange_satisfies_all_thirty_two_overlapping_ends() {
    let ends = vec![json!({"redis":{"operation":"GET","key":"done:*"}}); 32];
    let live = scope(resources(json!(ends)));
    let recorded = scope(live.rule.end.clone());
    observe_both(&live, &recorded, &redis("GET", b"done:42"), true);
    assert_eq!(live.completion.matched_mask(), u32::MAX);
}

#[test]
fn overlapping_occurrences_count_from_admission_and_duplicates_cannot_complete_them() {
    let ends = resources(json!([
        {"redis":{"operation":"DEL","key":"done:*"}},
        {"redis":{"operation":"DEL","key":"done:*","occurrence":2}}
    ]));
    let live = scope(ends.clone());
    let recorded = scope(ends);
    let initial = redis("DEL", b"done:42");
    observe_both(&live, &recorded, &initial, false);
    observe_both(&live, &recorded, &initial, false);
    observe_both(&live, &recorded, &redis("DEL", b"done:43"), false);
    observe_both(&live, &recorded, &redis("DEL", b"done:42"), true);
}

#[test]
fn all_mysql_ends_in_one_transaction_are_confirmed_together_only_by_commit() {
    let ends = resources(json!([
        {"mysql":{"sql":"UPDATE tasks SET status = 'completed' WHERE id = ?"}},
        {"mysql":{"sql":"UPDATE tasks SET revision = ? WHERE id = ?"}}
    ]));
    for commit in [true, false] {
        let live = scope(ends.clone());
        let recorded = scope(ends.clone());
        let mut update = mysql("UPDATE tasks SET status='completed' WHERE id=42", None);
        if let RecorderEvent::MysqlExchange(event) = &mut update {
            event.query_sequence = 7;
            event.server_status_before = Some(1);
            event.response.server_status = Some(1);
        }
        observe_both(&live, &recorded, &update, false);
        let mut second = update.clone();
        if let RecorderEvent::MysqlExchange(event) = &mut second {
            event.id = Uuid::new_v4();
            event.query_sequence = 8;
            event.sql = Some("UPDATE tasks SET revision=2 WHERE id=42".into());
        }
        observe_both(&live, &recorded, &second, false);
        let mut boundary = second;
        if let RecorderEvent::MysqlExchange(event) = &mut boundary {
            event.id = Uuid::new_v4();
            event.query_sequence = 9;
            event.sql = Some(if commit { "COMMIT" } else { "ROLLBACK" }.into());
            event.response.server_status = Some(2);
        }
        observe_both(&live, &recorded, &boundary, commit);
    }
}

#[test]
fn compound_sql_cannot_preserve_pending_ends_across_an_unproven_transaction_boundary() {
    let live = scope(vec![end()]);
    let recorded = scope(vec![end()]);
    let mut event = mysql("UPDATE tasks SET status='completed' WHERE id=42", None);
    if let RecorderEvent::MysqlExchange(event) = &mut event {
        event.query_sequence = 7;
        event.server_status_before = Some(1);
        event.response.server_status = Some(1);
    }
    observe_both(&live, &recorded, &event, false);
    if let RecorderEvent::MysqlExchange(event) = &mut event {
        event.id = Uuid::new_v4();
        event.query_sequence = 8;
        event.sql = Some("ROLLBACK; BEGIN".into());
    }
    observe_both(&live, &recorded, &event, false);
    if let RecorderEvent::MysqlExchange(event) = &mut event {
        event.id = Uuid::new_v4();
        event.query_sequence = 9;
        event.sql = Some("COMMIT".into());
        event.response.server_status = Some(2);
    }
    observe_both(&live, &recorded, &event, false);
}
