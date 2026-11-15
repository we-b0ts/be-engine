//! Derived delivery copies. Protocol adapters own their framing and lifecycle.
use crate::{
    value_codec::DecodedValue,
    value_contract::json::{AnchorClocks, Comparison},
};
use anyhow::{Result, ensure};
use serde_json::Value;

pub(crate) trait IdentityDeliveryHost {
    fn translate_identity_plan(
        &self,
        case: &str,
        source: &Value,
        delivered: &mut Value,
        global: &crate::policy::CompiledJsonPolicy,
    ) -> Result<(
        crate::value_contract::identities::IdentityDecision,
        Vec<String>,
    )>;
}

mod sse;
pub(crate) use sse::SseDelivery;
#[derive(Debug, Clone)]
pub(crate) struct Delivery {
    decoded: DecodedValue,
    global: crate::policy::CompiledJsonPolicy,
    clocks: AnchorClocks,
    source_validation: Comparison,
    copies: Vec<CopiedTime>,
}

#[derive(Debug, Clone)]
pub(crate) struct CopiedTime {
    pub pointer: String,
    pub value: serde_json::Value,
    pub proof: crate::value_contract::json::VerifiedTimeCopy,
}

impl Delivery {
    pub(crate) fn prepare_global(
        source: &[u8],
        global: &crate::policy::CompiledJsonPolicy,
        clocks: AnchorClocks,
    ) -> Result<Self> {
        let codec = crate::value_codec::compile(&crate::policy::Codec::Json)?;
        let decoded = codec.decode(source)?;
        Self::prepare_decoded_global(decoded, global, clocks)
    }

    pub(crate) fn prepare_decoded_global(
        decoded: DecodedValue,
        global: &crate::policy::CompiledJsonPolicy,
        clocks: AnchorClocks,
    ) -> Result<Self> {
        let source_clock =
            |pair: crate::value_contract::time::ClockPair| crate::value_contract::time::ClockPair {
                source: pair.source,
                target: pair.source,
            };
        let source_clocks = AnchorClocks {
            case: source_clock(clocks.case),
            dependency: source_clock(clocks.dependency),
            delivery: source_clock(clocks.delivery),
            observation: clocks.observation.map(source_clock),
        };
        let check = crate::value_contract::global::compare_decoded(
            &decoded,
            &decoded,
            global,
            &[],
            source_clocks,
        )?;
        ensure!(
            check.passed(),
            "Source response does not satisfy its declared contract: {:?}",
            check.differences
        );
        Ok(Self {
            decoded,
            global: global.clone(),
            clocks,
            source_validation: check,
            copies: Vec::new(),
        })
    }

    pub(crate) fn render(&self, now: chrono::DateTime<chrono::Utc>) -> Result<Vec<u8>> {
        let mut clocks = self.clocks;
        clocks.delivery.target = Some(now);
        if self.copies.is_empty() {
            return crate::value_contract::global::materialize_decoded(
                &self.decoded,
                &self.global,
                &[],
                clocks,
            );
        }
        let (logical, allowed) = self.logical_with_copies(clocks)?;
        self.decoded.encode(&logical, &allowed)
    }

    pub(crate) fn with_copies(mut self, copies: Vec<CopiedTime>) -> Self {
        self.copies = copies;
        self
    }

    fn logical_with_copies(
        &self,
        clocks: AnchorClocks,
    ) -> Result<(serde_json::Value, Vec<String>)> {
        let mut logical = crate::value_contract::global::materialize_logical(
            &self.decoded.logical,
            &self.global,
            &[],
            clocks,
        )?;
        let selected = self
            .global
            .selected_fields_with_clocks(&self.decoded.logical, clocks)?;
        let mut allowed = Vec::new();
        for selected in selected {
            let pointer = selected.pointer;
            let contract = selected.contract;
            let Some(time) = contract.time() else {
                continue;
            };
            let copy = self.copies.iter().find(|copy| copy.pointer == pointer);
            // Recognition alone never translates a textual time. An exact
            // counterpart from a proven preceding write/read is a stored copy,
            // independent of whether its format was authored or recognized.
            if selected.origin == traffic_policy_value::fields::FieldOrigin::Inferred
                && copy.is_none()
            {
                continue;
            }
            allowed.push(pointer.clone());
            if let Some(copy) = copy {
                let source =
                    self.decoded.logical.pointer(&pointer).ok_or_else(|| {
                        anyhow::anyhow!("stored timestamp Source field disappeared")
                    })?;
                ensure!(
                    copy.proof.permits_value(
                        selected.rule_id,
                        &pointer,
                        &pointer,
                        source,
                        &copy.value,
                        &time
                    ),
                    "stored timestamp delivery lacks authenticated provenance"
                );
                *logical.pointer_mut(&pointer).ok_or_else(|| {
                    anyhow::anyhow!("stored timestamp delivery field disappeared")
                })? = copy.value.clone();
            }
        }
        Ok((logical, allowed))
    }

    pub(crate) fn validation(&self) -> &Comparison {
        &self.source_validation
    }

    pub(crate) fn has_identities(&self) -> bool {
        self.global.fields.values().any(|field| field.is_identity()
            || matches!(field, crate::policy::GlobalField::Template { .. })
            || matches!(field,crate::policy::GlobalField::Url {formats} if formats == &[crate::policy::GlobalUrlFormat::Url]))
    }

    /// Render both derived time and identity fields from one immutable decode.
    /// The protocol owner commits the returned proposal before exposing bytes.
    pub(crate) fn render_with_identities(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        owner: &dyn IdentityDeliveryHost,
        case: &str,
    ) -> Result<(Vec<u8>, crate::value_contract::identities::IdentityDecision)> {
        let mut clocks = self.clocks;
        clocks.delivery.target = Some(now);
        let (mut logical, copied_allowed) = self.logical_with_copies(clocks)?;
        let (decision, mut allowed) = owner.translate_identity_plan(
            case,
            &self.decoded.logical,
            &mut logical,
            &self.global,
        )?;
        allowed.extend(copied_allowed);
        allowed.extend(
            self.global
                .delivery_fields_with_clocks(&self.decoded.logical, clocks)?
                .into_iter()
                .filter_map(|(pointer, field)| field.time().map(|_| pointer)),
        );
        Ok((self.decoded.encode(&logical, &allowed)?, decision))
    }
}

#[cfg(test)]
mod tests;
