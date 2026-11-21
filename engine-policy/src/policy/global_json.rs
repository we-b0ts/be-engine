//! One format declaration for every decoded JSON payload, independent of carrier.
use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::FieldContract;

mod template;
pub use template::GlobalTemplateFormat;

pub use traffic_policy_value::fields::SelectedGlobalField;
pub use traffic_policy_value::fields::{
    GLOBAL_JSON_ID, GlobalField, GlobalIdentityFormat, GlobalTimeFormat,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonPolicy {
    #[serde(deserialize_with = "super::strict_map::unique_map")]
    pub fields: BTreeMap<String, GlobalField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompiledJsonPolicy {
    pub fields: BTreeMap<String, GlobalField>,
    pub time: super::TimePolicy,
    pub fingerprint: String,
    #[serde(skip)]
    pub signatures: super::signatures::SignatureRegistry,
}

impl JsonPolicy {
    pub fn compile(&self) -> Result<CompiledJsonPolicy> {
        self.compile_with_signatures(&BTreeMap::new())
    }

    pub fn compile_with_signatures(
        &self,
        signatures: &BTreeMap<String, super::SignatureDefinition>,
    ) -> Result<CompiledJsonPolicy> {
        self.compile_with_settings(signatures, &super::TimePolicy::default())
    }

    pub fn compile_with_settings(
        &self,
        signatures: &BTreeMap<String, super::SignatureDefinition>,
        time: &super::TimePolicy,
    ) -> Result<CompiledJsonPolicy> {
        traffic_policy_value::fields::validate_fields(
            &self.fields,
            time,
            traffic_extensions::policies(),
        )?;
        Ok(CompiledJsonPolicy {
            fields: self.fields.clone(),
            time: time.clone(),
            fingerprint: super::digest(
                "traffic-policy/global-json/v2",
                &(self, signatures, time, traffic_extensions::semantics()),
            )?,
            signatures: super::signatures::SignatureRegistry::new(
                signatures,
                &self
                    .fields
                    .values()
                    .filter_map(|field| match field {
                        GlobalField::Jwt { signature } => Some(signature.clone()),
                        _ => None,
                    })
                    .collect(),
            )?,
        })
    }
}

pub trait GlobalFieldRuntime {
    fn validate(&self) -> Result<()>;
    fn select_contract(&self, source: &Value) -> Result<FieldContract>;
    fn select_contract_with_clock(
        &self,
        source: &Value,
        clock: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<FieldContract>;
}
impl GlobalFieldRuntime for GlobalField {
    fn validate(&self) -> Result<()> {
        self.validate_with_registry(traffic_extensions::policies())
    }
    fn select_contract(&self, source: &Value) -> Result<FieldContract> {
        self.select_contract_with_registry(source, None, traffic_extensions::policies())
    }
    fn select_contract_with_clock(
        &self,
        source: &Value,
        clock: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<FieldContract> {
        self.select_contract_with_registry(source, clock, traffic_extensions::policies())
    }
}

impl CompiledJsonPolicy {
    fn plan(&self) -> traffic_policy_value::fields::FieldPlan<'_> {
        traffic_policy_value::fields::FieldPlan::new(
            &self.fields,
            &self.time,
            traffic_extensions::policies(),
        )
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn fields(&self, source: &Value) -> Result<Vec<(String, FieldContract)>> {
        self.fields_with_clocks(source, traffic_contract::compare::AnchorClocks::default())
    }
    pub fn identity_fields(&self, source: &Value) -> Result<Vec<(String, FieldContract)>> {
        self.plan().identity_fields(source)
    }
    pub fn fields_with_clocks(
        &self,
        source: &Value,
        clocks: traffic_contract::compare::AnchorClocks,
    ) -> Result<Vec<(String, FieldContract)>> {
        self.plan().fields_with_clocks(source, clocks)
    }
    #[allow(dead_code)]
    pub fn delivery_fields_with_clocks(
        &self,
        source: &Value,
        clocks: traffic_contract::compare::AnchorClocks,
    ) -> Result<Vec<(String, FieldContract)>> {
        self.plan().delivery_fields_with_clocks(source, clocks)
    }
    pub fn selected_delivery_fields_with_clocks(
        &self,
        source: &Value,
        clocks: traffic_contract::compare::AnchorClocks,
    ) -> Result<Vec<SelectedGlobalField>> {
        self.plan()
            .selected_delivery_fields_with_clocks(source, clocks)
    }
    pub fn selected_fields_with_clocks(
        &self,
        source: &Value,
        clocks: traffic_contract::compare::AnchorClocks,
    ) -> Result<Vec<SelectedGlobalField>> {
        self.plan().selected_fields_with_clocks(source, clocks)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn comparison_fields(
        &self,
        source: &Value,
        target: &Value,
        clocks: traffic_contract::compare::AnchorClocks,
    ) -> Result<Vec<(String, FieldContract)>> {
        self.plan().comparison_fields(source, target, clocks)
    }
}

pub use traffic_contract::rule::is_schema_clock_group;

#[cfg(test)]
mod tests;
