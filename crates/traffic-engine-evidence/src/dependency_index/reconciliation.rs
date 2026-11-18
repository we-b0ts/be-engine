//! Off-path resource/operation discovery across the complete Source inventory.
//! A discovery edge is never a match, ownership proof or consumption receipt.
use super::{FileIndex, RecordLocation};
use crate::dependency::{attribution::DependencyOwner, observation::CaptureMetadata};
use crate::policy::{Database, Resource};
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    protocol: String,
    host: String,
    port: u16,
    database: Option<String>,
    username: Option<String>,
    operation: String,
}

#[derive(Debug)]
struct Entry {
    capture: CaptureMetadata,
    location: RecordLocation,
}

#[derive(Debug, Default)]
pub struct Catalog {
    by_resource: HashMap<Key, Vec<Entry>>,
    unindexed: BTreeMap<String, usize>,
}

fn family(protocol: &str, operation: &str) -> String {
    let command = operation
        .split_ascii_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if protocol == "mysql" && matches!(command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE") {
        "sql".into()
    } else {
        command
    }
}

fn host(value: &str) -> String {
    value
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn source_key(value: &Value) -> Option<Key> {
    let tag = value["event_type"].as_str()?;
    let protocol = if tag == "dependency_connect_failure" {
        value["protocol"].as_str()?
    } else {
        tag.split('_').next()?
    };
    let (host_name, port) = if protocol == "http" {
        let authority: hyper::http::uri::Authority = value["authority"].as_str()?.parse().ok()?;
        let default = if value["scheme"]
            .as_str()
            .is_some_and(|scheme| scheme.contains("https"))
        {
            443
        } else {
            80
        };
        (
            host(authority.host()),
            authority.port_u16().unwrap_or(default),
        )
    } else {
        (
            host(value["target_host"].as_str()?),
            u16::try_from(value["target_port"].as_u64()?).ok()?,
        )
    };
    let operation = if protocol == "http" {
        value["method"].as_str()?
    } else {
        value["command"].as_str()?
    };
    Some(Key {
        protocol: protocol.into(),
        host: host_name,
        port,
        database: value
            .get("database")
            .filter(|v| !v.is_null())
            .map(|v| v.to_string()),
        username: value["username"].as_str().map(str::to_owned),
        operation: family(protocol, operation),
    })
}

impl Catalog {
    pub fn from_index(index: &FileIndex) -> Result<Self> {
        let mut catalog = Self::default();
        for record in index.proof_records.as_ref().into_iter().flatten() {
            let Some(raw) = record.selector.get("capture") else {
                continue;
            };
            let capture: CaptureMetadata = serde_json::from_value(raw.clone())?;
            if !capture.semantic_required {
                continue;
            }
            if let Some(key) = source_key(&record.selector) {
                catalog.by_resource.entry(key).or_default().push(Entry {
                    capture,
                    location: record.location.clone(),
                });
            } else {
                let protocol = record.selector["event_type"]
                    .as_str()
                    .unwrap_or("unknown")
                    .split('_')
                    .next()
                    .unwrap_or("unknown");
                *catalog.unindexed.entry(protocol.into()).or_default() += 1;
            }
        }
        Ok(catalog)
    }

    pub fn discover(
        &self,
        target: &Value,
        owners: &BTreeMap<Uuid, DependencyOwner>,
        offset: usize,
        limit: usize,
    ) -> Value {
        let resource: Resource = match serde_json::from_value(target["resource"].clone()) {
            Ok(resource) => resource,
            Err(_) => {
                return json!({"status":"unavailable","reason":"authenticated Target resource metadata is unavailable","exact_match_evaluated":false});
            }
        };
        let protocol = serde_json::to_value(resource.protocol)
            .expect("protocol serializes")
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let database = resource.database.as_ref().map(|database| match database {
            Database::Index(index) => json!(index).to_string(),
            Database::Name(name) => json!(name).to_string(),
        });
        let key = Key {
            protocol: protocol.clone(),
            host: host(&resource.endpoint.host),
            port: resource.endpoint.port,
            database,
            username: resource.username,
            operation: family(&protocol, target["operation"].as_str().unwrap_or_default()),
        };
        let entries = self
            .by_resource
            .get(&key)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let omitted = self.unindexed.get(&protocol).copied().unwrap_or_default();
        let page = entries.iter().skip(offset).take(limit.min(100)).map(|entry| {
            let owner = owners.get(&entry.capture.exchange_id).unwrap_or(&entry.capture.attribution);
            let current = match owner {DependencyOwner::Case{origin_case_id,..}=>Some(origin_case_id.to_string()) == target["case_id"].as_str().map(str::to_owned),_=>false};
            json!({"source_exchange_id":entry.capture.exchange_id,"captured_owner":entry.capture.attribution,
                "effective_owner":owner,"observed_case":entry.capture.observed_case,
                "scope_relation":if current {"current_case"} else {"requires_scope_review"},
                "original_location":entry.location,"comparison":"payload_not_compared","consumption":"unavailable_for_this_attempt"})
        }).collect::<Vec<_>>();
        let returned = page.len();
        json!({"status":if entries.is_empty() {"no_resource_operation_candidate"} else {"comparison_required"},
            "basis":"physical resource and native command family only; SQL values, JSON and Redis args/keys remain untested",
            "exact_match_evaluated":false,"ownership_proved":false,"consumption_authorized":false,
            "coverage":{"indexed_protocol":protocol,"unindexed_records":omitted,"complete":omitted==0},
            "total":entries.len(),"offset":offset,"returned":returned,"items":page,
            "next_offset":(offset.saturating_add(returned)<entries.len()).then_some(offset.saturating_add(returned)),
            "conclusion_limit":"No discovery candidate does not establish async behavior, missing capture or a Target bug."})
    }
}

#[cfg(test)]
mod tests;
