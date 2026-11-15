//! Bounded, carrier-independent string templates with complete identity leaves.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::{GlobalField, GlobalIdentityFormat};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalTemplateFormat {
    pub template: String,
    #[serde(deserialize_with = "traffic_value::selector_map::unique_map")]
    pub fields: BTreeMap<String, GlobalIdentityFormat>,
}

impl GlobalTemplateFormat {
    pub(super) fn validate_with_registry(
        &self,
        policies: &traffic_policy::PolicyRegistry,
    ) -> Result<()> {
        let names = traffic_contract::template::validate_template(&self.template)?;
        ensure!(
            names == self.fields.keys().cloned().collect(),
            "template fields must exactly match its named slots"
        );
        for format in self.fields.values() {
            GlobalField::Identity {
                formats: vec![format.clone()],
            }
            .validate_with_registry(policies)?;
        }
        Ok(())
    }
}
