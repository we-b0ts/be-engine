//! Later carriers may retain the exact typed times actually delivered by dependencies.
//! These private fingerprints do not grant a new time format or a clock fallback.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DeliveredTimeCopies<S: CopyRuleScope> {
    #[serde(skip)]
    _scope: std::marker::PhantomData<S>,
    pairs: Vec<ResponseTimeCopy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseTimeCopy {
    source: [u8; 32],
    target: [u8; 32],
    deliveries: Vec<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
}

impl<S: CopyRuleScope> TimeCopyStore<S> {
    pub fn delivered_copies(&self, case: &str) -> DeliveredTimeCopies<S> {
        let pairs = self
            .cases
            .get(case)
            .into_iter()
            .flat_map(|case| &case.entries)
            .filter(|(_, value)| !value.deliveries.is_empty())
            .filter_map(|(key, value)| {
                Some(ResponseTimeCopy {
                    source: key.source,
                    target: value.target?,
                    deliveries: value
                        .deliveries
                        .iter()
                        .map(|delivery| delivery.clocks)
                        .collect(),
                })
            })
            .collect();
        DeliveredTimeCopies {
            pairs,
            _scope: std::marker::PhantomData,
        }
    }
}

impl<S: CopyRuleScope> DeliveredTimeCopies<S> {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.pairs
                .iter()
                .map(|pair| pair.deliveries.len().max(1))
                .sum::<usize>()
                <= MAX_CASE_COPIES,
            "delivered time provenance exceeds its bound"
        );
        Ok(())
    }

    pub fn proofs_with(
        &self,
        select: impl FnOnce() -> Result<Vec<TimeCopyLeaf>>,
        observed: ClockPair,
    ) -> Result<Vec<VerifiedTimeCopy<S>>> {
        self.validate()?;
        if self.pairs.is_empty() {
            return Ok(vec![]);
        }
        let Ok(observed) = observed.require() else {
            return Ok(vec![]);
        };
        let mut proofs = Vec::new();
        for leaf in select()? {
            if !S::permits(leaf.rule_id) {
                continue;
            }
            let source = time_hash(&leaf.value, &leaf.time)?;
            for pair in self.pairs.iter().filter(|pair| {
                pair.source == source
                    && pair
                        .deliveries
                        .iter()
                        .any(|&(a, b)| a <= observed.0 && b <= observed.1)
            }) {
                proofs.push(VerifiedTimeCopy {
                    _scope: std::marker::PhantomData,
                    rule_id: leaf.rule_id.into(),
                    source_pointer: leaf.pointer.clone(),
                    target_pattern: leaf.pattern.clone(),
                    source,
                    target: pair.target,
                    typed: true,
                });
                ensure!(
                    proofs.len() <= MAX_CASE_COPIES,
                    "delivered time proof expansion exceeds its bound"
                );
            }
        }
        Ok(proofs)
    }
}
