//! Derived delivery copies. Protocol adapters own their framing and lifecycle.
pub(in crate::replay) use crate::value_contract::encoded::compare;
#[cfg(test)]
use crate::value_contract::encoded::merged_codec;
use crate::{
    policy::CompiledRule,
    value_codec::DecodedValue,
    value_contract::json::{AnchorClocks, Comparison},
};
use anyhow::{Result, ensure};
#[derive(Debug, Clone)]
pub(in crate::replay) struct Delivery {
    original: Vec<u8>,
    decoded: DecodedValue,
    rules: Vec<CompiledRule>,
    clocks: AnchorClocks,
    source_validation: Comparison,
}

impl Delivery {
    pub(in crate::replay) fn prepare(
        source: &[u8],
        rules: &[&CompiledRule],
        clocks: AnchorClocks,
    ) -> Result<Self> {
        let codec = crate::value_contract::encoded::prepared_codec(rules)?;
        let decoded = codec.decode(source)?;
        for rule in rules {
            for pointer in rule.delivery_time.keys() {
                ensure!(
                    crate::value_contract::json::pointer_observed(&decoded.logical, pointer),
                    "Source delivery timestamp {pointer:?} was not observed"
                );
            }
        }
        let source_clock =
            |pair: crate::value_contract::time::ClockPair| crate::value_contract::time::ClockPair {
                source: pair.source,
                target: pair.source,
            };
        let check = crate::value_contract::encoded::compare_decoded(
            &decoded,
            &decoded,
            rules,
            AnchorClocks {
                case: source_clock(clocks.case),
                dependency: source_clock(clocks.dependency),
                delivery: source_clock(clocks.delivery),
            },
        )?;
        ensure!(
            check.passed(),
            "Source response does not satisfy its declared contract: {:?}",
            check.differences
        );
        Ok(Self {
            original: source.into(),
            decoded,
            rules: rules.iter().map(|rule| (*rule).clone()).collect(),
            clocks,
            source_validation: check,
        })
    }

    pub(in crate::replay) fn render(&self, now: chrono::DateTime<chrono::Utc>) -> Result<Vec<u8>> {
        if self.rules.iter().all(|rule| rule.delivery_time.is_empty()) {
            return Ok(self.original.clone());
        }
        let mut clocks = self.clocks;
        clocks.delivery.target = Some(now);
        let rules = self.rules.iter().collect::<Vec<_>>();
        crate::value_contract::encoded::materialize_decoded(&self.decoded, &rules, clocks)
    }

    pub(in crate::replay) fn validation(&self) -> &Comparison {
        &self.source_validation
    }

    pub(in crate::replay) fn has_identities(&self) -> bool {
        crate::value_contract::identities::rules_have_identity(
            &self.rules.iter().collect::<Vec<_>>(),
        )
    }

    /// Render both derived time and identity fields from one immutable decode.
    /// The protocol owner commits the returned proposal before exposing bytes.
    pub(in crate::replay) fn render_with_identities(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        owner: &crate::replay::policy::request_contract::RequestContracts,
        case: &str,
    ) -> Result<(Vec<u8>, crate::value_contract::identities::IdentityDecision)> {
        let rules = self.rules.iter().collect::<Vec<_>>();
        // Conditions always see the immutable Source document, before any
        // derived delivery time can alter a sibling used by a guard.
        let selected = crate::value_contract::identities::select(&self.decoded.logical, &rules)?;
        let entries = selected
            .iter()
            .map(|field| field.delivery)
            .collect::<Vec<_>>();
        let (values, decision) = owner.identity_deliveries(case, &entries)?;
        let mut clocks = self.clocks;
        clocks.delivery.target = Some(now);
        let mut logical =
            crate::value_contract::delivery::materialize(&self.decoded.logical, &rules, clocks)?;
        let mut allowed = rules
            .iter()
            .flat_map(|rule| rule.delivery_time.keys().cloned())
            .collect::<Vec<_>>();
        for (field, value) in selected.iter().zip(values) {
            *logical
                .pointer_mut(&field.pointer)
                .ok_or_else(|| anyhow::anyhow!("identity delivery field disappeared"))? = value;
            allowed.push(field.pointer.clone());
        }
        Ok((self.decoded.encode(&logical, &allowed)?, decision))
    }
}

#[cfg(test)]
mod tests;
