//! Bind native MySQL value projection to application policy and protected evidence.
use super::*;
use crate::policy::CompiledPolicy;
pub(super) use native::delivery::{translate_selection, write_value};
pub(crate) use native::{Metadata, Selection, time_leaves};
use traffic_policy_execution::ExecutionContext;
use traffic_policy_value::{fields::ScalarFormat, formats::FormatHost};
use traffic_protocol_mysql::{sql::field_bindings::FieldIdentity, value_rules as native};
pub(crate) type RequestContext<'a> = native::RequestContext<'a, CompiledPolicy>;
mod witness;
pub(crate) use witness::{validate_source_witness, validate_witness_with_time_copies};

impl native::ValuePolicy for CompiledPolicy {
    fn execution(&self) -> ExecutionContext<'_> {
        crate::value_contract::execution_context()
    }
    fn document(&self) -> Option<&dyn FormatHost> {
        self.global_json
            .as_ref()
            .map(|plan| plan as &dyn FormatHost)
    }
    fn scalar_formats(&self) -> Option<&dyn native::ScalarFormats> {
        self.mysql
            .as_ref()
            .map(|mysql| mysql as &dyn native::ScalarFormats)
    }
    fn uses_native_types(&self) -> bool {
        self.mysql.is_some() || self.global_json.is_some()
    }
}

pub(crate) fn compare_selection_with_context(
    selected: &Selection,
    clocks: AnchorClocks,
    copies: &[crate::value_contract::json::VerifiedTimeCopy],
    policy: &CompiledPolicy,
) -> Result<Comparison> {
    native::compare_selection_with_context(
        selected,
        clocks,
        &crate::value_contract::copy_proofs(copies),
        policy,
    )
}

#[cfg(test)]
use native::{Temporal, temporal_selection};

#[allow(clippy::too_many_arguments)]
pub(super) fn response_selection(
    policy: &CompiledPolicy,
    response: &RecordedMysqlResponse,
    index: usize,
    source: &RecordedMysqlValue,
    target: &RecordedMysqlValue,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
) -> Result<Option<Selection>> {
    native::response_selection(
        policy, response, index, source, target, sql, database, clocks,
    )
}
pub(crate) fn compare_response(
    policy: &CompiledPolicy,
    source: &RecordedMysqlResponse,
    target: &RecordedMysqlResponse,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    native::compare_response(policy, source, target, sql, database, clocks)
}
pub(super) fn compare_input_response(
    policy: &CompiledPolicy,
    source: &RecordedMysqlResponse,
    target: &RecordedMysqlResponse,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    native::compare_input_response(policy, source, target, sql, database, clocks)
}
pub(super) fn has_response_contracts(
    policy: &CompiledPolicy,
    source: &RecordedMysqlResponse,
    sql: Option<&str>,
    database: Option<&str>,
    clocks: AnchorClocks,
) -> Result<bool> {
    native::has_response_contracts(policy, source, sql, database, clocks)
}

impl native::ScalarFormats for crate::policy::MysqlPolicy {
    fn field(&self, origin: &FieldIdentity) -> Result<Option<&dyn ScalarFormat>> {
        self.field(&origin.table, &origin.column)
            .map(|field| field.map(|field| field as &dyn ScalarFormat))
    }
}
