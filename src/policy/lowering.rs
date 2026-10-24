//! Pure lowering of resource-owned fields into the existing value-rule pipeline.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};

use super::*;

#[derive(Debug, Clone, PartialEq)]
pub struct ExpandedPolicy {
    pub rules: Vec<PolicyRule>,
    /// Authoring locations are diagnostics, never part of runtime identity.
    pub origins: BTreeMap<String, String>,
    /// Every selected leaf retains its complete, revision-bound Source proof.
    pub field_proofs: BTreeMap<String, BTreeMap<String, Proof>>,
}

pub fn effective_rules(document: &TrafficPolicy) -> Result<Vec<PolicyRule>> {
    Ok(lower_policy(document)?.rules)
}

/// Automatic groups carry no authored cross-field clock relationship.
pub fn is_schema_clock_group(group: &str) -> bool {
    group.strip_prefix("schema.").is_some_and(|value| {
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn field_strategy(
    field: &FieldContract,
    selector: &MatchSpec,
    slot: &Slot,
    pointer: &str,
) -> Result<FieldContract> {
    let mut field = field.clone();
    let leaf = match &mut field {
        FieldContract::Conditional { contract, .. } => contract.as_mut(),
        other => other,
    };
    if let FieldContract::Time {
        clock_group,
        format,
        ..
    } = leaf
    {
        if let Some(group) = clock_group {
            ensure!(
                !group.starts_with("schema."),
                "schema. clock groups are reserved for implicit field clocks"
            );
        } else if *format != TimestampFormat::CalendarDate {
            let identity = digest("traffic-policy/schema-clock/v2", &(selector, slot, pointer))?;
            *clock_group = Some(format!("schema.{}", &identity[7..39]));
        }
    }
    Ok(field)
}

pub fn lower_policy(document: &TrafficPolicy) -> Result<ExpandedPolicy> {
    ensure!(
        document.rules.len() <= 4096,
        "policy contains more than 4096 rules"
    );
    ensure!(
        document.responses.len() <= 4096,
        "policy contains more than 4096 response declarations"
    );
    ensure!(
        document
            .rules
            .iter()
            .all(|rule| !rule.id().starts_with("schema:")),
        "schema: rule ids are reserved for generated resource and response declarations"
    );
    let document = super::authoring::expanded(document)?;
    let mut lower = Lowering {
        revision: document.source_revision.as_deref(),
        leaf_count: 0,
        output: ExpandedPolicy {
            rules: document.rules.clone(),
            origins: BTreeMap::new(),
            field_proofs: BTreeMap::new(),
        },
    };
    for (name, declaration) in &document.resources {
        identifier(name)?;
        let resource = &declaration.resource;
        resource.endpoint.validate()?;
        ensure!(
            declaration.tables.is_empty() || resource.protocol == Protocol::Mysql,
            "resource {name:?}: tables require protocol mysql"
        );
        ensure!(
            declaration.keys.is_empty() || resource.protocol == Protocol::Redis,
            "resource {name:?}: keys require protocol redis"
        );
        let resource_proof = inherited(None, declaration.proof.as_ref());
        for (table_name, table) in &declaration.tables {
            ensure!(
                !table.fields.is_empty(),
                "table {table_name:?} has no declared fields"
            );
            let mut selector = MatchSpec {
                resource: Some(resource.clone()),
                tables: table.tables.clone(),
                table_patterns: table.table_patterns.clone(),
                table_series: table.table_series.clone(),
                ..Default::default()
            };
            if selector.tables.is_empty()
                && selector.table_patterns.is_empty()
                && selector.table_series.is_none()
            {
                if table_name.contains('*') {
                    selector.table_patterns.push(table_name.clone());
                } else {
                    selector.tables.push(table_name.clone());
                }
            }
            crate::config::mysql_tables::TableMatcher::new(
                &selector.tables,
                &selector.table_patterns,
                selector.table_series.as_ref(),
            )?;
            let table_proof = inherited(Some(&resource_proof), table.proof.as_ref());
            for (column, field) in &table.fields {
                let origin = format!("resources.{name}.tables.{table_name}.fields.{column}");
                let payload = match field {
                    ColumnDeclaration::Decoded(payload) => payload.clone(),
                    ColumnDeclaration::Scalar { field, delivery } => PayloadDeclaration {
                        codec: Codec::Scalar,
                        proof: None,
                        fields: BTreeMap::from([(String::new(), field.clone())]),
                        delivery: delivery.clone(),
                    },
                };
                for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
                    lower.payload(
                        surface,
                        selector.clone(),
                        Slot::SqlField(column.clone()),
                        &payload,
                        Some(&table_proof),
                        None,
                        &origin,
                    )?;
                }
            }
        }
        for (index, key) in declaration.keys.iter().enumerate() {
            let proof = inherited(Some(&resource_proof), key.proof.as_ref());
            let selector = MatchSpec {
                resource: Some(resource.clone()),
                key: Some(key.key.clone()),
                hash_field: key.hash_field.clone(),
                ..Default::default()
            };
            for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
                lower.payload(
                    surface,
                    selector.clone(),
                    Slot::RedisValue(key.container),
                    &key.value,
                    Some(&proof),
                    None,
                    &format!("resources.{name}.keys[{index}].value"),
                )?;
            }
        }
    }
    for (name, response) in &document.responses {
        identifier(name)?;
        let proof = inherited(None, response.proof.as_ref());
        ensure!(
            response.body.is_some() || !response.sse.is_empty(),
            "response {name:?} has no body or SSE fields"
        );
        let selector = MatchSpec {
            api: Some(response.api.clone()),
            ..Default::default()
        };
        if let Some(body) = &response.body {
            lower.payload(
                Surface::ApiResponse,
                selector.clone(),
                Slot::Body,
                body,
                Some(&proof),
                response.when.clone(),
                &format!("responses.{name}.body"),
            )?;
        }
        for (index, sse) in response.sse.iter().enumerate() {
            let payload = PayloadDeclaration {
                codec: sse.codec.clone(),
                proof: sse.proof.clone(),
                fields: sse.fields.clone(),
                delivery: None,
            };
            lower.payload(
                Surface::ApiResponse,
                selector.clone(),
                Slot::SseData(sse.event.clone()),
                &payload,
                Some(&proof),
                response.when.clone(),
                &format!("responses.{name}.sse[{index}]"),
            )?;
        }
    }
    Ok(lower.output)
}

fn identifier(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)),
        "declaration names require 1..128 ASCII identifier characters"
    );
    Ok(())
}

fn inherited(
    parent: Option<&DeclarationProof>,
    local: Option<&DeclarationProof>,
) -> DeclarationProof {
    let mut value = parent.cloned().unwrap_or_default();
    if let Some(local) = local {
        if local.source.is_some() {
            value.source.clone_from(&local.source);
        }
        if local.fact.is_some() {
            value.fact.clone_from(&local.fact);
        }
    }
    value
}

struct Lowering<'a> {
    revision: Option<&'a str>,
    leaf_count: usize,
    output: ExpandedPolicy,
}

impl Lowering<'_> {
    #[allow(clippy::too_many_arguments)]
    fn payload(
        &mut self,
        surface: Surface,
        selector: MatchSpec,
        slot: Slot,
        payload: &PayloadDeclaration,
        parent: Option<&DeclarationProof>,
        when: Option<SourceCondition>,
        origin: &str,
    ) -> Result<()> {
        ensure!(
            !payload.fields.is_empty() && payload.fields.len() <= 128,
            "{origin}: requires 1..128 fields"
        );
        ensure!(
            self.output.rules.len() < 4096,
            "policy expands to more than 4096 rules"
        );
        self.leaf_count += payload.fields.len();
        ensure!(
            self.leaf_count <= 16384,
            "policy expands to more than 16384 declared field contracts"
        );
        ensure!(
            payload.delivery.is_none() || surface != Surface::ApiResponse,
            "{origin}: API responses cannot declare delivery"
        );
        let scope = inherited(parent, payload.proof.as_ref());
        let mut proofs = BTreeMap::new();
        let mut fields = BTreeMap::new();
        for (pointer, field) in &payload.fields {
            let proof = inherited(Some(&scope), field.proof.as_ref());
            let raw = serde_yaml::to_value(proof)?;
            let resolved = super::authoring::resolve_declaration_proof(raw, self.revision)
                .with_context(|| format!("{origin}.fields[{pointer:?}]"))?;
            let proof: Proof = serde_yaml::from_value(resolved)?;
            proof.validate(false)?;
            fields.insert(
                pointer.clone(),
                field_strategy(&field.contract, &selector, &slot, pointer)?,
            );
            proofs.insert(pointer.clone(), proof);
        }
        let id = format!(
            "schema:{}",
            digest(
                "traffic-policy/schema-location/v2",
                &(surface, &selector, &slot, &payload.codec, &when)
            )?
            .trim_start_matches("sha256:")
        );
        ensure!(
            !self.output.origins.contains_key(&id),
            "{origin}: duplicates an existing resource-owned payload scope"
        );
        let proof = proofs.values().next().expect("nonempty fields").clone();
        let rule = Rule {
            id: id.clone(),
            surface,
            selector,
            slot,
            codec: payload.codec.clone(),
            contract: fields,
            proof,
            delivery: if surface == Surface::DependencyResponse {
                payload.delivery.clone()
            } else {
                None
            },
            when,
        };
        self.output.origins.insert(id.clone(), origin.into());
        self.output.field_proofs.insert(id, proofs);
        self.output.rules.push(rule.into());
        Ok(())
    }
}
