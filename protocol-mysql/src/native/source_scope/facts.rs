//! Keep only the evidence used to prove native MySQL session dispositions.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use traffic_protocol::{connection::SessionDecision, evidence::SessionScopeFacts};

use crate::recorded::RecordedMysqlExchange;

pub(super) struct ScopeRecord {
    pub(super) exchange: RecordedMysqlExchange,
    pub(super) complete: bool,
}

impl ScopeRecord {
    pub(super) fn capture(event: &Value) -> Result<Self> {
        let response = event["response"]
            .as_object()
            .context("MySQL exchange has no response facts")?;
        let mut facts = without(
            event.as_object().context("invalid MySQL exchange")?,
            "response",
        );
        facts.insert("response".into(), Value::Object(without(response, "rows")));
        let mut exchange: RecordedMysqlExchange = serde_json::from_value(Value::Object(facts))?;
        exchange.response.row_shape = Some(match response.get("rows") {
            Some(rows) => {
                let rows = rows
                    .as_array()
                    .context("MySQL response rows are not an array")?;
                let width = exchange.response.columns.len();
                (
                    rows.len(),
                    rows.iter()
                        .all(|row| row.as_array().is_some_and(|cols| cols.len() == width)),
                )
            }
            None => (0, true),
        });
        Ok(Self {
            exchange,
            complete: event["capture_complete"] == true,
        })
    }
}

fn without(
    fields: &serde_json::Map<String, Value>,
    omitted: &str,
) -> serde_json::Map<String, Value> {
    fields
        .iter()
        .filter(|(name, _)| name.as_str() != omitted)
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

#[derive(Default)]
pub(crate) struct ScopeFacts(BTreeMap<usize, ScopeRecord>);

impl SessionScopeFacts for ScopeFacts {
    fn observe(&mut self, event: &Value) -> Result<()> {
        if event["event_type"] == "mysql_exchange" {
            let sequence = event["capture"]["sequence"]
                .as_u64()
                .filter(|&seq| seq > 0)
                .context("MySQL Session exchange has no admission sequence")?;
            ensure!(
                self.0
                    .insert(usize::try_from(sequence)?, ScopeRecord::capture(event)?)
                    .is_none(),
                "multiple MySQL Session exchanges at sequence {sequence}"
            );
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<SessionDecision>> {
        let plan = super::prepare_session_facts(&self.0)?;
        let mut decisions = Vec::with_capacity(plan.steps.len() + plan.driver_prelude.len());
        for (position, step) in plan.steps {
            if !self.0[&position]
                .exchange
                .capture
                .as_ref()
                .is_some_and(|capture| capture.semantic_required)
            {
                continue;
            }
            decisions.push(SessionDecision {
                sequence: u64::try_from(position)?,
                step: Some(step),
                driver_prelude: None,
            });
        }
        for (position, driver_prelude) in plan.driver_prelude {
            decisions.push(SessionDecision {
                sequence: u64::try_from(position)?,
                step: None,
                driver_prelude: Some(driver_prelude),
            });
        }
        Ok(decisions)
    }
}
