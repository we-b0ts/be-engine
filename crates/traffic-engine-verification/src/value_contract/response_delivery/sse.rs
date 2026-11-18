//! Derived copies of upstream SSE data reuse the global JSON field strategy.
use super::*;
use crate::replay::policy::values::ValueDecision;

#[allow(dead_code)]
pub struct SseDelivery {
    document: crate::value_codec::sse::Document,
    values: Vec<Option<Delivery>>,
    validation: Comparison,
}

impl SseDelivery {
    #[allow(dead_code)]
    pub fn prepare(
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

    #[allow(dead_code)]
    pub fn validation(&self) -> &Comparison {
        &self.validation
    }

    #[allow(dead_code)]
    pub fn render(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        owner: &dyn IdentityDeliveryHost,
        case: &str,
    ) -> Result<(Vec<u8>, ValueDecision)> {
        let mut decision = ValueDecision {
            comparison: self.validation.clone(),
            identity: None,
        };
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
