//! Redis evidence formats bind native notification facts to shared artifact storage.
use crate::dependency_index::Paged;
use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
use traffic_protocol::report::ReportSection;
pub(crate) mod notifications;
pub(crate) mod shared;
use notifications::{NotificationEvidence, RedisEvidence};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fields {
    #[serde(default)]
    notifications: Option<NotificationEvidence>,
}
struct Extension {
    value: Option<NotificationEvidence>,
}
impl ReportSection for Extension {
    fn count(&self) -> Result<usize> {
        Ok(self.value.as_ref().map_or(0, NotificationEvidence::count))
    }
    fn read(
        &self,
        report: &Path,
        offset: usize,
        limit: usize,
        items: &mut Vec<Value>,
    ) -> Result<()> {
        if let Some(value) = &self.value {
            value.read(report, offset, limit, items)?;
        }
        Ok(())
    }
    fn stage(&self, source: &Path, destination: &Path) -> Result<Value> {
        Ok(match &self.value {
            Some(value) => json!({"notifications": value.stage(source, destination)?}),
            None => json!({}),
        })
    }
}
struct Legacy {
    pages: Paged<Value>,
    value: RedisEvidence,
}
impl ReportSection for Legacy {
    fn count(&self) -> Result<usize> {
        self.value.count()
    }
    fn read(
        &self,
        report: &Path,
        offset: usize,
        limit: usize,
        items: &mut Vec<Value>,
    ) -> Result<()> {
        self.pages.read_into(offset, limit, items)?;
        if items.len() < limit && offset < self.value.count()? {
            self.value.read_notifications(
                report,
                offset.saturating_sub(self.pages.count),
                limit,
                items,
            )?;
        }
        Ok(())
    }
    fn stage(&self, source: &Path, destination: &Path) -> Result<Value> {
        let mut value = self.value.clone();
        value.stage(source, destination)?;
        Ok(serde_json::to_value(value)?)
    }
}
pub(crate) fn decode_extensions(
    report: &Path,
    fields: &BTreeMap<String, Value>,
) -> Result<Box<dyn ReportSection>> {
    let fields: Fields = serde_json::from_value(serde_json::to_value(fields)?)?;
    if let Some(value) = &fields.notifications {
        value.load(report)?;
    }
    Ok(Box::new(Extension {
        value: fields.notifications,
    }))
}
pub(crate) fn decode(report: &Path, value: &Value) -> Result<Option<Box<dyn ReportSection>>> {
    let Some(value) = RedisEvidence::parse(value)? else {
        return Ok(None);
    };
    value.load(report)?;
    let root = report
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Global report has no parent"))?;
    let pages = Paged::restore(value.pages.clone().resolve(root)?)?;
    Ok(Some(Box::new(Legacy { pages, value })))
}
pub(crate) fn fields(value: Option<NotificationEvidence>) -> Result<BTreeMap<String, Value>> {
    Ok(match value {
        Some(value) => BTreeMap::from([("notifications".into(), serde_json::to_value(value)?)]),
        None => BTreeMap::new(),
    })
}
