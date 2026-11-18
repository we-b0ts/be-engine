//! Empty native report extensions still reject unknown persisted fields.
use super::ReportSection;
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fields {
    #[serde(default)]
    notifications: Option<Value>,
}

pub(super) fn decode(fields: &BTreeMap<String, Value>) -> Result<Box<dyn ReportSection>> {
    let fields: Fields = serde_json::from_value(serde_json::to_value(fields)?)?;
    ensure!(
        fields.notifications.is_none(),
        "Global inventory protocol differs from its report section"
    );
    Ok(Box::new(Empty))
}

struct Empty;
impl ReportSection for Empty {
    fn count(&self) -> Result<usize> {
        Ok(0)
    }
    fn read(&self, _: &Path, _: usize, _: usize, _: &mut Vec<Value>) -> Result<()> {
        Ok(())
    }
    fn stage(&self, _: &Path, _: &Path) -> Result<Value> {
        Ok(serde_json::json!({}))
    }
}
