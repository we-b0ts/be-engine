use super::*;
use traffic_protocol::ProtocolId;
use traffic_replay::{
    EventKind, ReplaySource, SequenceBinding, SequencePlan, SequenceRuntime, SourceEvent,
    exchange::{ExchangeInventory, MatchContext, Selection, SourceContext},
};

const PREFIX: &str =
    "SELECT items.id FROM items WHERE items.kind='Team' AND (items.owner,items.name) IN ";
const SOURCE_ROWS: &str = "((1,'one'),(2,'two'),(1,'one'))";
const REORDERED_ROWS: &str = "((2,'two'),(1,'one'),(1,'one'))";

fn request(rows: &str) -> RequestMessage {
    RequestMessage {
        command: "COM_QUERY".into(),
        sql: Some(format!("{PREFIX}{rows} ORDER BY items.id")),
        params: None,
        database: Some("app".into()),
        username: Some("user".into()),
    }
}

#[test]
fn the_native_session_accepts_typed_tuple_permutations_with_original_evidence() {
    let protocol = ProtocolId::new("mysql");
    let mut record = event();
    record["sql"] = json!(request(SOURCE_ROWS).sql);
    let exchange = Native.recorded_exchange(&record).unwrap().unwrap();
    let endpoint = exchange.endpoint.clone();
    let mut inventory = ExchangeInventory::default();
    inventory
        .register(
            protocol,
            exchange,
            SourceContext {
                source: ReplaySource::Startup,
                case_id: None,
                position: 1,
                capture: None,
            },
            Default::default(),
        )
        .unwrap();
    inventory.seal();
    let actual = request(REORDERED_ROWS);
    assert_eq!(actual.project().unwrap().values["/literals/1"].bytes, "2");
    let select = |inventory: &ExchangeInventory, actual: &RequestMessage| {
        inventory
            .select(
                MatchContext {
                    protocol,
                    endpoint: &endpoint,
                    active_case: None,
                    request: actual,
                    session: None,
                    lane: None,
                    request_session: None,
                    metadata: &(),
                },
                |_| (),
                |_, _| Ok(()),
            )
            .unwrap()
    };
    assert!(matches!(select(&inventory, &actual), Selection::NotFound));
    let plan = SequencePlan::compile([
        SourceEvent {
            sequence: 1,
            dependency_sequence: 1,
            kind: EventKind::Request,
            offset_micros: 0,
        },
        SourceEvent {
            sequence: 2,
            dependency_sequence: 1,
            kind: EventKind::ResponseEnd,
            offset_micros: 1,
        },
    ])
    .unwrap();
    inventory
        .lifecycle
        .sequence
        .attach_run(SequenceBinding::new(
            SequenceRuntime::with_session_timing(plan, None, []),
            [(0, 1)].into_iter(),
        ));
    assert!(
        matches!(select(&inventory, &actual), Selection::Matched(selected) if selected.index == 0)
    );
    assert_eq!(actual.project().unwrap().values["/literals/1"].bytes, "2");
    assert!(matches!(
        select(&inventory, &request("((1,'two'),(2,'one'),(1,'one'))")),
        Selection::NotFound
    ));
}

#[test]
fn tuple_permutation_keeps_literals_types_duplicates_and_outer_sql_strict() {
    let source = request(SOURCE_ROWS);
    assert!(request(REORDERED_ROWS).exact_request_reordering_of(&source));
    for rows in [
        "((1,'one'),(2,'two'),(2,'two'))",
        "((2,'two'),(1,'one'))",
        "((1,'two'),(2,'one'),(1,'one'))",
        "(('2','two'),(1,'one'),(1,'one'))",
        "((2,'two'),(1,'one'),(?,'one'))",
        "((2,'two'),(1,'one'),(1,'one',9))",
    ] {
        assert!(
            !request(rows).exact_request_reordering_of(&source),
            "{rows}"
        );
    }
    for (before, after) in [
        ("'Team'", "'Bot'"),
        ("ORDER BY items.id", "ORDER BY items.owner"),
        (") IN", ") NOT IN"),
        ("SELECT items.id", "SELECT RAND()"),
        ("ORDER BY items.id", "ORDER BY items.id FOR UPDATE"),
    ] {
        let mut actual = request(REORDERED_ROWS);
        actual.sql = actual.sql.map(|sql| sql.replace(before, after));
        assert!(!actual.exact_request_reordering_of(&source), "{after}");
    }
}
