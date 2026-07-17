use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::AppState;
use crate::active_case::DependencyTargets;
use crate::recorder::{MysqlExchangeEvent, MysqlResponseEvent, RecorderEvent};

#[derive(Clone, Default)]
pub(super) struct QueryDependencyOwnerships {
    by_sequence: Arc<Mutex<HashMap<u64, DependencyTargets>>>,
}

impl QueryDependencyOwnerships {
    pub(super) fn insert(&self, sequence: u64, ownership: DependencyTargets) {
        self.by_sequence
            .lock()
            .expect("MySQL dependency ownerships poisoned")
            .insert(sequence, ownership);
    }

    pub(super) fn get(&self, sequence: u64) -> Option<DependencyTargets> {
        self.by_sequence
            .lock()
            .expect("MySQL dependency ownerships poisoned")
            .get(&sequence)
            .cloned()
    }

    pub(super) fn take(&self, sequence: u64) -> Option<DependencyTargets> {
        self.by_sequence
            .lock()
            .expect("MySQL dependency ownerships poisoned")
            .remove(&sequence)
    }
}

pub(super) async fn record_query_completion(
    state: &AppState,
    ownerships: &QueryDependencyOwnerships,
    response: Option<MysqlResponseEvent>,
    exchange: Option<MysqlExchangeEvent>,
) -> Result<()> {
    let sequence = response
        .as_ref()
        .map(|response| response.query_sequence)
        .or_else(|| exchange.as_ref().map(|exchange| exchange.query_sequence));
    let ownership = sequence.and_then(|sequence| ownerships.take(sequence));
    if let Some(response) = response {
        record_event(
            state,
            RecorderEvent::MysqlResponse(response),
            ownership.as_ref(),
        )
        .await?;
    }
    if let Some(exchange) = exchange {
        record_event(
            state,
            RecorderEvent::MysqlExchange(exchange),
            ownership.as_ref(),
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn record_event(
    state: &AppState,
    event: RecorderEvent,
    ownership: Option<&DependencyTargets>,
) -> Result<()> {
    state.recorder().record(event.clone()).await?;
    if let Some(ownership) = ownership {
        state.record_dependency_for_targets(&event, ownership).await;
    }
    Ok(())
}
