//! Derived copies of upstream SSE data reuse the global JSON field strategy.
use super::*;
use crate::replay::policy::request_contract::{Decision, RequestContracts};

pub(in crate::replay) struct SseDelivery {
    document: crate::value_codec::sse::Document,
    values: Vec<Option<Delivery>>,
    validation: Comparison,
}

impl SseDelivery {
    pub(in crate::replay) fn prepare(
        source: &[u8],
        plan: &crate::policy::CompiledJsonPolicy,
        clocks: AnchorClocks,
    ) -> Result<Self> {
        let document = crate::value_codec::sse::Document::decode(source)?;
        let mut validation = Comparison::default();
        let mut values = Vec::new();
        for (index, event) in document.events.iter().enumerate() {
            let value = if crate::json_value::parse(event.data.as_bytes()).is_some() {
                let delivery = Delivery::prepare_global(event.data.as_bytes(), plan, clocks)?;
                let mut checked = delivery.validation().clone();
                checked.scope_schema_clocks(index);
                validation.merge_and_validate(checked);
                Some(delivery)
            } else {
                None
            };
            values.push(value);
        }
        ensure!(
            validation.passed(),
            "Source SSE field relationships changed"
        );
        Ok(Self {
            document,
            values,
            validation,
        })
    }

    pub(in crate::replay) fn validation(&self) -> &Comparison {
        &self.validation
    }

    pub(in crate::replay) fn render(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        owner: &RequestContracts,
        case: &str,
    ) -> Result<(Vec<u8>, Decision)> {
        let mut decision = Decision::from_value_comparison(self.validation.clone());
        let mut values = Vec::new();
        for (event, value) in self.document.events.iter().zip(&self.values) {
            let value = if let Some(value) = value {
                if value.has_identities() {
                    let (bytes, identity) = value.render_with_identities(now, owner, case)?;
                    if let Some(existing) = &mut decision.identity {
                        existing.merge(identity)?;
                    } else {
                        decision.identity = Some(identity);
                    }
                    bytes
                } else {
                    value.render(now)?
                }
            } else {
                event.data.as_bytes().to_vec()
            };
            values.push(value);
        }
        Ok((self.document.render(&values)?, decision))
    }
}
