//! Protocol admission and immutable envelopes stay outside the encoded value core.
use crate::{
    policy::{Database, Protocol, Surface},
    policy_evidence::WitnessRef,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::Path;

pub(in crate::rewrite::unified_rule) fn protocol(event: &Value) -> Option<Protocol> {
    match event["event_type"].as_str()? {
        "redis_exchange" => Some(Protocol::Redis),
        "memcached_exchange" => Some(Protocol::Memcached),
        "http_exchange" => Some(Protocol::Http),
        "mysql_exchange" => Some(Protocol::Mysql),
        _ => None,
    }
}

pub(in crate::rewrite) fn source_witness(
    surface: Surface,
    event: &Value,
    key_context: &Path,
) -> Result<Vec<u8>> {
    let providers = crate::protocols::default_providers();
    let owner = providers
        .event_provider(event)
        .context("dependency evidence owner is unavailable")?;
    providers
        .evidence()
        .source_payload(
            owner.kind.as_str(),
            event,
            surface.dependency_side()?,
            &crate::request_headers::SourceSecrets::new(key_context),
        )?
        .context("native Source payload projection is unavailable")
}

pub(in crate::rewrite::unified_rule) fn validate_metadata(
    witness: &WitnessRef,
    event: &Value,
) -> Result<()> {
    if protocol(event) == Some(Protocol::Http) {
        return crate::protocols::replay::http_witness_metadata_matches(event, &witness.metadata);
    }
    let resource = witness
        .metadata
        .resource
        .as_ref()
        .context("witness has no protocol identity")?;
    ensure!(
        protocol(event) == Some(resource.protocol)
            && event["target_host"]
                .as_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(&resource.endpoint.host))
            && event["target_port"].as_u64() == Some(u64::from(resource.endpoint.port))
            && resource
                .database
                .as_ref()
                .map(|d| database_matches(d, &event["database"]))
                .unwrap_or(event["database"].is_null())
            && resource.username.as_deref() == event["username"].as_str()
            && event["command"]
                .as_str()
                .is_some_and(|actual| actual.eq_ignore_ascii_case(&witness.metadata.operation)),
        "Target witness protocol identity differs from its immutable Source exchange"
    );
    Ok(())
}

pub(in crate::rewrite) fn values(
    surface: Surface,
    event: &Value,
    raw: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    match protocol(event).context("unsupported dependency event")? {
        Protocol::Redis
            if surface == Surface::DependencyResponse
                && crate::policy::runtime::redis_bulk_payload(raw)?.is_none() =>
        {
            Ok(vec![])
        }
        Protocol::Redis => Ok(vec![(
            super::arguments(event)?
                .into_iter()
                .next()
                .context("Redis key is missing")?,
            super::redis_payload(surface, event, raw)?,
        )]),
        Protocol::Memcached => {
            anyhow::bail!("Memcached recording has no installed protocol implementation")
        }
        Protocol::Http => Ok(crate::protocols::replay::http_witness_value(raw, surface)?
            .map(|payload| vec![(Vec::new(), payload)])
            .unwrap_or_default()),
        _ => anyhow::bail!("selected protocol requires its native value-slot extractor"),
    }
}

fn database_matches(database: &Database, observed: &Value) -> bool {
    match database {
        Database::Index(index) => observed.as_i64() == Some(*index),
        Database::Name(name) => observed.as_str() == Some(name),
    }
}

pub(in crate::rewrite) fn source_identity(
    case: &str,
    event: &Value,
) -> Option<crate::policy_evidence::SourceIdentity> {
    let providers = crate::protocols::default_providers();
    let reference = providers.evidence().finite_reference(event).ok()??;
    let fields = reference.fields();
    let identity = crate::policy_evidence::SourceIdentity {
        case_id: case.into(),
        exchange_id: fields
            .get("exchange_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        connection_id: fields
            .get("connection_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        sequence: fields.get("sequence").and_then(Value::as_u64),
    };
    (identity.exchange_id.is_some()
        || identity.connection_id.is_some() && identity.sequence.is_some())
    .then_some(identity)
}
