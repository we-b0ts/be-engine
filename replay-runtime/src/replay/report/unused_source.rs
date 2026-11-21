use super::*;
pub use traffic_engine_replay::replay::report::unused_source::*;
fn select_case<P: ReplayProtocolSet>(
    state: &RuntimeState<P>,
    case: &str,
    wanted: &BTreeSet<Uuid>,
) -> BTreeMap<Uuid, Option<CaptureFact>> {
    if let Some(deferred) = &state.deferred {
        let records = deferred
            .files
            .get(case)
            .and_then(|case| case.index.proof_records.as_ref());
        fold(records.into_iter().flatten().filter_map(|record| {
            let selector = &record.selector;
            let id = selector["capture"]["exchange_id"]
                .as_str()?
                .parse::<Uuid>()
                .ok()?;
            wanted
                .contains(&id)
                .then(|| CaptureFact::parse(selector, selector["_capture_complete"] == true))
                .flatten()
        }))
    } else {
        fold(
            state
                .eager_source_facts
                .get(case)
                .into_iter()
                .flatten()
                .filter(|fact| wanted.contains(&fact.capture.exchange_id))
                .cloned(),
        )
    }
}
pub(crate) fn attach<P: ReplayProtocolSet>(state: &RuntimeState<P>, report: &mut Value) -> usize {
    let Some(identity) = &state.source_inventory_id else {
        return 0;
    };
    let mut cases = BTreeMap::<String, Vec<SourceRow>>::new();
    for row in state
        .native
        .source_occurrence_rows(report)
        .into_iter()
        .chain(P::source_occurrence_rows(state, report))
    {
        cases.entry(row.case.clone()).or_default().push(row);
    }
    let mut published = 0;
    for (case, rows) in cases {
        let wanted = rows.iter().map(|row| row.exchange_id).collect();
        let facts = select_case(state, &case, &wanted);
        for source in rows {
            let Some(Some(fact)) = facts.get(&source.exchange_id) else {
                continue;
            };
            let matches = match source.identity {
                SourceIdentity::Reference(reference) => reference == fact.capture.protocol_ref,
                SourceIdentity::EventType(event_type) => event_type == fact.event_type,
            };
            if !matches {
                continue;
            }
            let Some(row) = report.pointer_mut(&source.pointer) else {
                continue;
            };
            if row["case_id"].as_str() != Some(&case) {
                continue;
            }
            row[OCCURRENCE] = serde_json::json!(SourceOccurrence {
                source_exchange_id: source.exchange_id,
                captured_owner: fact.capture.attribution.clone(),
                capture_complete: fact.complete,
            });
            published += 1;
        }
    }
    report[INVENTORY] = serde_json::json!(identity);
    published
}
