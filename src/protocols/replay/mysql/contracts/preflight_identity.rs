//! Derived comparison copies compose attested identities with ordinary SQL fields.
use super::*;
use crate::policy::{CompiledPolicy, Resource};
use std::{borrow::Cow, collections::BTreeSet};

pub(crate) struct IdentityPreflight<'a> {
    pub policy: &'a CompiledPolicy,
    pub report: &'a Value,
    pub case: &'a str,
    pub request: &'a Value,
    pub dependencies: &'a [u8],
    pub resource: &'a Resource,
    pub clocks: AnchorClocks,
}

pub(crate) struct NormalizedIdentityWitnesses {
    pub source: Vec<u8>,
    pub target: Vec<u8>,
    pub rule_ids: BTreeSet<String>,
}

pub(crate) fn normalize_identity_witnesses(
    context: IdentityPreflight<'_>,
    source: &[u8],
    target: &[u8],
) -> Result<Option<NormalizedIdentityWitnesses>> {
    if serde_json::from_slice::<Value>(source)?
        .get("response")
        .is_some()
    {
        return Ok(None);
    }
    ensure!(
        context.resource.protocol == crate::policy::Protocol::Mysql,
        "identity preflight requires MySQL resource"
    );
    let mut source: RequestEnvelope = serde_json::from_slice(source)?;
    let mut target: RequestEnvelope = serde_json::from_slice(target)?;
    validate_request_clocks(&source, &target, context.clocks)?;
    if !structurally_related(&source, &target)? {
        return Ok(None);
    }
    let identity = ReplaySessionIdentity {
        target: Some(TargetKey {
            host: context.resource.endpoint.host.clone(),
            port: context.resource.endpoint.port,
        }),
        database: context
            .resource
            .database
            .as_ref()
            .and_then(|d| d.name())
            .map(str::to_owned),
        username: context.resource.username.clone(),
    };
    let policy_context = crate::policy::runtime::MysqlPolicyContext {
        request_times: traffic_contract::time::ClockPair {
            source: context.clocks.dependency.source,
            target: context.clocks.dependency.target,
        },
        case_id: Some(context.case),
        identity: &identity,
        command: &target.command,
        recorded_sql: source.sql.as_deref(),
        recorded: source.params.as_deref(),
        sql: target.sql.as_deref(),
        actual: target.params.as_deref(),
    };
    let (aliases, rule_ids) = policy::dynamic_values::from_native_report(
        context.policy,
        context.report,
        &policy_context,
        context.request,
        context.dependencies,
    )?;
    if rule_ids.is_empty() {
        return Ok(None);
    }
    let Some(normalized) = aliases.mysql(&policy_context) else {
        return Ok(None);
    };
    let normalized = normalized?;
    if normalized.source_sql.as_deref() == source.sql.as_deref()
        && normalized.source_params.as_deref() == source.params.as_deref()
        && normalized.actual_sql.as_deref() == target.sql.as_deref()
        && normalized.actual_params.as_deref() == target.params.as_deref()
    {
        return Ok(None);
    }
    ensure!(
        context.clocks.dependency.source.is_some(),
        "SQL identity Source clock missing"
    );
    let (source_sql, source_params, target_sql, target_params) = (
        normalized.source_sql.map(Cow::into_owned),
        normalized.source_params.map(Cow::into_owned),
        normalized.actual_sql.map(Cow::into_owned),
        normalized.actual_params.map(Cow::into_owned),
    );
    source.sql = source_sql;
    source.params = source_params;
    target.sql = target_sql;
    target.params = target_params;
    Ok(Some(NormalizedIdentityWitnesses {
        source: serde_json::to_vec(&source)?,
        target: serde_json::to_vec(&target)?,
        rule_ids,
    }))
}
