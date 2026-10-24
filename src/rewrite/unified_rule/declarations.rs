//! Add resource-owned permissions without changing established scopes or proofs.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};

use crate::policy::{
    ColumnDeclaration, MysqlTableDeclaration, PayloadDeclaration, ResourceDeclaration,
    ResponseDeclaration, TrafficPolicy,
};

pub(super) fn merge(document: &mut TrafficPolicy, proposed: &TrafficPolicy) -> Result<bool> {
    let mut candidate = document.clone();
    for (name, resource) in &proposed.resources {
        if let Some(current) = candidate.resources.get_mut(name) {
            merge_resource(current, resource)?;
        } else {
            candidate.resources.insert(name.clone(), resource.clone());
        }
    }
    for (name, response) in &proposed.responses {
        if let Some(current) = candidate.responses.get_mut(name) {
            merge_response(current, response)?;
        } else {
            candidate.responses.insert(name.clone(), response.clone());
        }
    }
    for (id, references) in &proposed.field_references {
        ensure!(
            proposed.rules.iter().any(|rule| rule.id() == id),
            "field references must belong to a proposed contextual rule"
        );
        candidate
            .field_references
            .insert(id.clone(), references.clone());
    }
    let changed = &candidate != document;
    *document = candidate;
    Ok(changed)
}

pub(super) fn validate_response_scope(document: &TrafficPolicy, active_api: &str) -> Result<()> {
    for response in document.responses.values() {
        ensure!(
            response.api == active_api,
            "response declaration belongs to another API issue"
        );
    }
    Ok(())
}

fn merge_resource(current: &mut ResourceDeclaration, proposed: &ResourceDeclaration) -> Result<()> {
    ensure!(
        current.resource == proposed.resource && current.proof == proposed.proof,
        "existing resource identity or inherited proof changed; preserve the established resource"
    );
    for (name, table) in &proposed.tables {
        if let Some(existing) = current.tables.get_mut(name) {
            merge_table(existing, table)?;
        } else {
            current.tables.insert(name.clone(), table.clone());
        }
    }
    for key in &proposed.keys {
        if let Some(existing) = current.keys.iter_mut().find(|existing| {
            existing.key == key.key
                && existing.container == key.container
                && existing.hash_field == key.hash_field
        }) {
            ensure!(
                existing.proof == key.proof,
                "Redis key inherited proof changed"
            );
            merge_payload(&mut existing.value, &key.value)?;
        } else {
            current.keys.push(key.clone());
        }
    }
    Ok(())
}

fn merge_table(
    current: &mut MysqlTableDeclaration,
    proposed: &MysqlTableDeclaration,
) -> Result<()> {
    let mut scope = proposed.clone();
    scope.fields = current.fields.clone();
    ensure!(
        &scope == current,
        "existing MySQL table scope or proof changed"
    );
    for (column, field) in &proposed.fields {
        if let Some(existing) = current.fields.get_mut(column) {
            match (existing, field) {
                (ColumnDeclaration::Decoded(existing), ColumnDeclaration::Decoded(field)) => {
                    merge_payload(existing, field)?;
                }
                (existing, field) => ensure!(
                    existing == field,
                    "existing scalar column contract or proof changed"
                ),
            }
        } else {
            current.fields.insert(column.clone(), field.clone());
        }
    }
    Ok(())
}

fn merge_payload(current: &mut PayloadDeclaration, proposed: &PayloadDeclaration) -> Result<()> {
    ensure!(
        current.codec == proposed.codec
            && current.proof == proposed.proof
            && current.delivery == proposed.delivery,
        "existing payload codec, proof or delivery changed"
    );
    merge_fields(&mut current.fields, &proposed.fields)
}

fn merge_fields<T: Clone + PartialEq>(
    current: &mut BTreeMap<String, T>,
    proposed: &BTreeMap<String, T>,
) -> Result<()> {
    for (path, contract) in proposed {
        if let Some(existing) = current.get(path) {
            ensure!(
                existing == contract,
                "existing field contract or proof changed at {path:?}"
            );
        } else {
            current.insert(path.clone(), contract.clone());
        }
    }
    Ok(())
}

fn merge_response(current: &mut ResponseDeclaration, proposed: &ResponseDeclaration) -> Result<()> {
    ensure!(
        current.api == proposed.api
            && current.when == proposed.when
            && current.proof == proposed.proof,
        "existing response scope, condition or proof changed"
    );
    if let Some(body) = &proposed.body {
        if let Some(existing) = &mut current.body {
            merge_payload(existing, body)?;
        } else {
            current.body = Some(body.clone());
        }
    }
    for sse in &proposed.sse {
        if let Some(existing) = current.sse.iter_mut().find(|old| old.event == sse.event) {
            ensure!(
                existing.codec == sse.codec && existing.proof == sse.proof,
                "existing SSE codec or proof changed"
            );
            merge_fields(&mut existing.fields, &sse.fields)?;
        } else {
            current.sse.push(sse.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn document(fields: Value) -> TrafficPolicy {
        crate::policy::parse_policy(
            &json!({
                "format":"traffic-policy/v2",
                "resources":{"cache":{
                    "protocol":"redis","endpoint":"cache.test:6379","database":0,
                    "keys":[{"key":{"prefix":"task:"},"container":"string",
                        "proof":{"source":"source.py:write","fact":"Source writes unordered sets"},
                        "value":{"codec":"json","fields":fields}}]
                }},"rules":[]
            })
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn additive_fields_preserve_resource_owned_authoring_and_effective_ids() {
        let mut current = document(json!({"/tags":"unordered"}));
        let proposed = document(json!({"/members":"unordered"}));
        let before = crate::policy::effective_rules(&current).unwrap();
        assert!(merge(&mut current, &proposed).unwrap());
        assert!(!merge(&mut current, &proposed).unwrap());
        assert_eq!(current.resources["cache"].keys[0].value.fields.len(), 2);
        let effective = crate::policy::effective_rules(&current).unwrap();
        assert_eq!(effective.len(), before.len());
        assert_eq!(effective[0].id(), before[0].id());
        let rendered = crate::policy::render_policy(&current).unwrap();
        let parsed = crate::policy::parse_policy(&rendered).unwrap();
        assert_eq!(parsed, current);
        assert!(parsed.rules.is_empty());
    }

    #[test]
    fn incompatible_resource_or_field_changes_do_not_mutate_current_document() {
        let current = document(json!({"/tags":"unordered"}));
        let mut variants = Vec::new();
        let mut other = current.clone();
        other
            .resources
            .get_mut("cache")
            .unwrap()
            .resource
            .endpoint
            .port = 6380;
        variants.push(other);
        let mut other = current.clone();
        other.resources.get_mut("cache").unwrap().keys[0]
            .proof
            .as_mut()
            .unwrap()
            .fact = Some("Different proof".into());
        variants.push(other);
        for proposed in variants {
            let mut candidate = current.clone();
            assert!(merge(&mut candidate, &proposed).is_err());
            assert_eq!(candidate, current);
        }
    }
}
