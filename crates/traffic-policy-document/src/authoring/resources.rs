//! Named resources expand only at schema-owned resource slots, never business JSON.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde_yaml::Value;

use crate::{Database, Protocol, Resource, ResourceDeclaration};

pub fn expand(rule: &mut Value, resources: &BTreeMap<String, ResourceDeclaration>) -> Result<()> {
    visit(rule, &mut |value| {
        if let Some(name) = value.as_str() {
            let declaration = resources
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("unknown resource reference {name:?}"))?;
            *value = serde_yaml::to_value(&declaration.resource)?;
        }
        Ok(())
    })
}

pub struct Names(BTreeMap<Vec<u8>, String>);

pub fn names(resources: &BTreeMap<String, ResourceDeclaration>) -> Result<Names> {
    let mut names = BTreeMap::new();
    for (name, definition) in resources {
        names
            .entry(serde_json::to_vec(&definition.resource)?)
            .or_insert_with(|| name.clone());
    }
    Ok(Names(names))
}

pub fn compact(rule: &mut Value, names: &Names) -> Result<()> {
    visit(rule, &mut |value| {
        let resource: Resource = serde_yaml::from_value(value.clone())?;
        if let Some(name) = names.0.get(&serde_json::to_vec(&resource)?) {
            *value = name.clone().into();
        }
        Ok(())
    })
}

pub fn resource(value: &mut Value, f: &mut impl FnMut(&mut Value) -> Result<()>) -> Result<()> {
    let value = unwrapped(value);
    if let Some(resource) = value.get_mut("resource") {
        f(resource)?;
    }
    Ok(())
}

pub fn unwrapped(value: &mut Value) -> &mut Value {
    if value.as_mapping().is_some_and(|map| {
        map.contains_key("contract")
            && map
                .keys()
                .all(|key| matches!(key.as_str(), Some("contract" | "proof")))
    }) {
        value.get_mut("contract").expect("checked")
    } else {
        value
    }
}

pub fn list(
    value: &mut Value,
    key: &str,
    f: &mut impl FnMut(&mut Value) -> Result<()>,
) -> Result<()> {
    if let Some(items) = value.get_mut(key) {
        let items = items
            .as_sequence_mut()
            .ok_or_else(|| anyhow::anyhow!("{key} requires a list"))?;
        for entry in items {
            resource(entry, f)?;
        }
    }
    Ok(())
}

pub fn visit(rule: &mut Value, f: &mut impl FnMut(&mut Value) -> Result<()>) -> Result<()> {
    if let Some(selector) = rule.get_mut("match") {
        resource(selector, f)?;
    }
    let Some(effect) = rule.get_mut("effect") else {
        return Ok(());
    };
    match effect.get("kind").and_then(Value::as_str).unwrap_or("") {
        "identity" => {
            list(effect, "references", f)?;
        }
        "response_jwt" => {
            if let Some(key) = effect.get_mut("signing_key") {
                resource(key, f)?;
            }
        }
        "process_owned" => {
            if let Some(origin) = effect.get_mut("origin") {
                let origin = unwrapped(origin);
                if let Some(capture) = origin.get_mut("capture") {
                    let capture = capture
                        .as_mapping_mut()
                        .ok_or_else(|| anyhow::anyhow!("origin capture requires a mapping"))?;
                    for (_, capture) in capture {
                        resource(capture, f)?;
                    }
                }
            }
            if let Some(selector) = effect.get_mut("selector") {
                if matches!(
                    selector.get("protocol").and_then(Value::as_str),
                    Some("redis_pubsub" | "redis_script")
                ) {
                    resource(selector, f)?;
                }
                if let Some(mysql) = selector.get_mut("selector") {
                    resource(mysql, f)?;
                }
                list(selector, "transaction_members", f)?;
            }
        }
        _ => (),
    }
    Ok(())
}

pub fn validate(resources: &BTreeMap<String, ResourceDeclaration>) -> Result<()> {
    ensure!(
        resources.len() <= 256,
        "policy contains more than 256 named resources"
    );
    for (name, definition) in resources {
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)),
            "invalid resource name {name:?}"
        );
        definition.resource.endpoint.validate()?;
        let resource = &definition.resource;
        ensure!(
            resource
                .username
                .as_ref()
                .is_none_or(|user| !user.is_empty()
                    && user.len() <= 256
                    && !user.contains(['\r', '\n', '\0'])),
            "resource {name:?}: invalid username"
        );
        match resource.protocol {
            Protocol::Mysql => ensure!(
                matches!(&resource.database, None | Some(Database::Name(_)))
                    && resource
                        .database
                        .as_ref()
                        .and_then(Database::name)
                        .is_none_or(|db| !db.is_empty() && db.len() <= 256),
                "resource {name:?}: MySQL database must be a bounded name"
            ),
            Protocol::Redis => ensure!(
                matches!(&resource.database, None | Some(Database::Index(0..))),
                "resource {name:?}: Redis database must be a nonnegative integer"
            ),
            Protocol::Http | Protocol::Memcached => ensure!(
                resource.database.is_none() && resource.username.is_none(),
                "resource {name:?}: HTTP/Memcached identities have no database or username"
            ),
        }
    }
    Ok(())
}
