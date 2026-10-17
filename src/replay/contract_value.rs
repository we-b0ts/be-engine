//! Derived delivery copies. Protocol adapters own their framing and lifecycle.
pub(in crate::replay) use crate::value_contract::encoded::{compare, merged_codec};
use crate::{
    policy::CompiledRule,
    value_codec::{CodecView, DecodedValue},
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
        let codec = merged_codec(rules)?;
        let decoded = CodecView::decode(&codec, source)?;
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
        let check = compare(
            source,
            source,
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
}
