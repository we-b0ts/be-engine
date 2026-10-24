//! Redis key formats reuse a virtual global JSON declaration at the scalar root.
use super::*;
use crate::policy::{
    CompiledJsonPolicy, GLOBAL_JSON_ID, GLOBAL_REDIS_ID, GlobalField, RedisPolicy,
};
use crate::replay::contract_value::Delivery;
use crate::value_contract::{
    json::{AnchorClocks, Comparison},
    redis_scalar::{self, Scalar},
};

#[derive(Debug, Clone)]
pub(in crate::replay::policy::request_contract) struct ScalarDelivery {
    source: Scalar,
    field: GlobalField,
    inner: Delivery,
    additional: Option<CompiledJsonPolicy>,
    clocks: AnchorClocks,
    validation: Comparison,
}

fn account(mut result: Comparison) -> Comparison {
    if result.evaluated.remove(GLOBAL_JSON_ID) {
        result.evaluated.insert(GLOBAL_REDIS_ID.into());
    }
    if let Some(count) = result.time_validations.remove(GLOBAL_JSON_ID) {
        result
            .time_validations
            .insert(GLOBAL_REDIS_ID.into(), count);
    }
    result
}

impl ScalarDelivery {
    pub(in crate::replay::policy::request_contract) fn prepare(
        source: Scalar,
        field: &GlobalField,
        additional: Option<&CompiledJsonPolicy>,
        clocks: AnchorClocks,
    ) -> Result<Self> {
        let inner = Delivery::prepare_global(
            &serde_json::to_vec(&source.logical)?,
            &redis_scalar::plan(field),
            clocks,
        )?;
        let validation = account(inner.validation().clone());
        let additional = additional
            .filter(|plan| source.json && plan.fields.contains_key(""))
            .cloned();
        Ok(Self {
            source,
            field: field.clone(),
            inner,
            additional,
            clocks,
            validation,
        })
    }
    pub(in crate::replay::policy::request_contract) fn validation(&self) -> &Comparison {
        &self.validation
    }
    pub(in crate::replay::policy::request_contract) fn has_identities(&self) -> bool {
        self.field.is_identity()
            || self
                .additional
                .as_ref()
                .is_some_and(|plan| plan.fields.values().any(GlobalField::is_identity))
    }
    fn finish(&self, logical: &Value, now: DateTime<Utc>) -> Result<Vec<u8>> {
        let mut clocks = self.clocks;
        clocks.delivery.target = Some(now);
        let bytes = self.source.encode(logical)?;
        let source = self.source.encode(&self.source.logical)?;
        let checked = redis_scalar::compare(&source, &bytes, &self.field, clocks, &[])?;
        ensure!(
            checked.passed(),
            "derived Redis scalar violates its key format: {:?}",
            checked.differences
        );
        if let Some(plan) = &self.additional {
            let checked = crate::value_contract::global::compare(
                &serde_json::to_vec(&self.source.logical)?,
                &serde_json::to_vec(logical)?,
                plan,
                &[],
                clocks,
            )?;
            ensure!(
                checked.passed(),
                "derived Redis scalar violates the JSON format: {:?}",
                checked.differences
            );
        }
        Ok(bytes)
    }
    pub(in crate::replay::policy::request_contract) fn render(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<u8>> {
        self.finish(
            &crate::json_value::parse(&self.inner.render(now)?)
                .context("derived Redis scalar JSON is invalid")?,
            now,
        )
    }
    pub(in crate::replay::policy::request_contract) fn render_with_identities(
        &self,
        now: DateTime<Utc>,
        owner: &RequestContracts,
        case: &str,
    ) -> Result<(Vec<u8>, crate::value_contract::identities::IdentityDecision)> {
        let (bytes, identity) = self.inner.render_with_identities(now, owner, case)?;
        let mut logical =
            crate::json_value::parse(&bytes).context("derived Redis scalar JSON is invalid")?;
        let mut decision = Decision {
            identity: Some(identity),
            ..Default::default()
        };
        if let Some(plan) = &self.additional {
            let (identity, _) =
                owner.translate_identity_plan(case, &self.source.logical, &mut logical, plan)?;
            owner.merge_identity_decision(&mut decision, identity)?;
        }
        Ok((
            self.finish(&logical, now)?,
            decision.identity.expect("Redis scalar identity proposal"),
        ))
    }
}

impl RequestContracts {
    pub(in crate::replay) fn redis_policy(&self) -> Option<&RedisPolicy> {
        self.compiled.as_ref()?.redis.as_ref()
    }

    pub(in crate::replay::policy::request_contract) fn scalar_delivery(
        &self,
        key: &[u8],
        payload: &[u8],
        clocks: AnchorClocks,
    ) -> Result<Option<ScalarDelivery>> {
        let Some(policy) = self.redis_policy() else {
            return Ok(None);
        };
        let Some(field) = policy.field(key)? else {
            return Ok(None);
        };
        let Some(source) = redis_scalar::decode_field(payload, field)? else {
            return Ok(None);
        };
        ScalarDelivery::prepare(source, field, self.global_json(), clocks).map(Some)
    }
}
