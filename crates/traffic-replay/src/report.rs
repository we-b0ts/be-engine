//! Native report projections enter shared immutable inventories and visibility accounting.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
mod usage;
pub use usage::{Change, Position, Usage};

#[derive(Debug, Clone, Copy)]
pub enum ReportRows {
    Core,
    Extras,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub position: Position,
    pub visible: bool,
    pub value: Value,
}

pub trait GlobalReportProjection {
    fn global_report_protocols(&self) -> Vec<String>;
    fn global_report_layout(&self, protocol: &str) -> Result<Vec<usize>>;
    fn global_report_semantics(&self, protocol: &str) -> Option<String>;
    fn global_report_is_stable(&self, protocol: &str) -> bool;
    fn visit_global_report(
        &self,
        protocol: &str,
        rows: ReportRows,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()>;
}

pub trait GlobalReportRuntime: GlobalReportProjection {
    fn global_report_snapshot(&self, protocol: &str) -> Result<(usize, Vec<Change>)>;
    fn initialize_global_report(&mut self, protocol: &str, visible: usize) -> Result<()>;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryDelta {
    pub lane: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumed: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub responding: Vec<usize>,
}

/// Read-only delivery observations projected from the owner's live finite inventory.
pub struct DeliverySession<Lane> {
    pub lanes: Vec<Lane>,
    pub deltas: Vec<DeliveryDelta>,
    pub recorded: usize,
    pub delivered: usize,
    pub failed: usize,
}

pub struct JoinedProjection<'a> {
    primary: &'a dyn GlobalReportProjection,
    registered: &'a dyn GlobalReportProjection,
}
impl<'a> JoinedProjection<'a> {
    pub fn new(
        primary: &'a dyn GlobalReportProjection,
        registered: &'a dyn GlobalReportProjection,
    ) -> Self {
        Self {
            primary,
            registered,
        }
    }
    fn owner(&self, protocol: &str) -> Result<&dyn GlobalReportProjection> {
        let primary = self
            .primary
            .global_report_protocols()
            .iter()
            .any(|id| id == protocol);
        let registered = self
            .registered
            .global_report_protocols()
            .iter()
            .any(|id| id == protocol);
        anyhow::ensure!(
            !(primary && registered),
            "Global report protocol has multiple inventory owners"
        );
        anyhow::ensure!(
            primary || registered,
            "Global report protocol has no inventory owner"
        );
        Ok(if registered {
            self.registered
        } else {
            self.primary
        })
    }
}
impl GlobalReportProjection for JoinedProjection<'_> {
    fn global_report_protocols(&self) -> Vec<String> {
        self.primary
            .global_report_protocols()
            .into_iter()
            .chain(self.registered.global_report_protocols())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    fn global_report_layout(&self, protocol: &str) -> Result<Vec<usize>> {
        self.owner(protocol)?.global_report_layout(protocol)
    }
    fn global_report_semantics(&self, protocol: &str) -> Option<String> {
        self.owner(protocol).ok()?.global_report_semantics(protocol)
    }
    fn global_report_is_stable(&self, protocol: &str) -> bool {
        self.owner(protocol)
            .is_ok_and(|owner| owner.global_report_is_stable(protocol))
    }
    fn visit_global_report(
        &self,
        protocol: &str,
        rows: ReportRows,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        self.owner(protocol)?
            .visit_global_report(protocol, rows, visitor)
    }
}
