//! Native value locations and output formats delegate value semantics to shared policy services.
use crate::{
    model::{MysqlColumn as RecordedMysqlColumn, MysqlValue as RecordedMysqlValue},
    recorded::{RecordedMysqlExchange, RecordedMysqlResponse},
    session_identity::SessionIdentity as ReplaySessionIdentity,
    sql::field_bindings::FieldIdentity,
    values,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};
use traffic_contract::{
    compare::{self as json, AnchorClocks, Comparison, Field},
    rule::FieldContract,
};
use traffic_policy_execution::ExecutionContext;
use traffic_policy_value::{
    fields::{GLOBAL_JSON_ID, ScalarFormat},
    formats::FormatHost,
};
pub const MYSQL_ID: &str = "global.mysql";
pub mod delivery;
pub mod fields;
mod metadata;
mod provenance;
mod request;
mod response;
mod selection;
use metadata::temporal;
pub use metadata::{Metadata, Temporal};
pub use provenance::{compare_selection_with_context, compare_selection_with_copies, time_leaves};
pub use request::RequestContext;
pub use response::{
    compare_input_response, compare_response, has_response_contracts, response_selection,
};
pub use selection::{Selection, compare_selection, temporal_selection};
use selection::{
    equivalent_midnight, global_scalar_selection, independent_scalar_contract, native_scalar,
};

/// Application-owned declarations and immutable services used at native value locations.
pub trait ValuePolicy {
    fn execution(&self) -> ExecutionContext<'_>;
    fn document(&self) -> Option<&dyn FormatHost>;
    fn scalar_formats(&self) -> Option<&dyn ScalarFormats>;
    fn uses_native_types(&self) -> bool;
}

/// Delivery retains the caller's identity ownership and publication transaction.
pub trait DeliveryHost: traffic_policy_value::host::ValueRuleHost {
    fn format_host(&self) -> Option<&dyn FormatHost>;
    fn translate_document_identity(
        &self,
        scope: &str,
        source: &Value,
        delivered: &mut Value,
    ) -> Result<traffic_contract::identity::IdentityDecision>;
}

/// Optional physical scalar declarations keep column origin analysis demand-driven.
pub trait ScalarFormats {
    fn field(&self, origin: &FieldIdentity) -> Result<Option<&dyn ScalarFormat>>;
}
