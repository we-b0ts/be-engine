use crate::{
    AnalysisInput, ComparisonPolicy, Evaluation, EvaluationHost, EvidenceAccess, Finding,
    PolicyAction, PolicyDefinition, PolicyDescriptor, PolicyProvider, TransformInput,
    TransformPlan, TransformPolicy, ValuePair,
};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, sync::Arc};
use traffic_value::Value;

#[derive(Clone, Default)]
pub struct PolicyRegistry {
    providers: BTreeMap<String, Arc<dyn PolicyProvider>>,
}

impl PolicyRegistry {
    pub fn select(
        &self,
        definitions: &[PolicyDefinition],
        source: &Value,
        facts: &Value,
    ) -> Result<Option<usize>> {
        let mut selected = None;
        let mut rank = 0;
        let mut ambiguous = false;
        let mut candidates = 0;
        let mut unranked = false;
        for (index, definition) in definitions.iter().enumerate() {
            let policy = self.prepare_definition(definition)?;
            match policy.implementation.source_match(source, facts)? {
                crate::SourceMatch::Inapplicable => (),
                crate::SourceMatch::Applicable => return Ok(Some(index)),
                crate::SourceMatch::Ranked(score) => {
                    candidates += 1;
                    unranked |= score.is_none();
                    let score = score.unwrap_or(0);
                    if selected.is_none() || score > rank {
                        selected = Some(index);
                        rank = score;
                        ambiguous = false;
                    } else if score == rank
                        && selected.is_some_and(|previous| definitions[previous] != *definition)
                    {
                        ambiguous = true;
                    }
                }
            }
        }
        Ok(selected.filter(|_| !ambiguous && (!unranked || candidates == 1)))
    }
    pub fn infer(&self, source: &Value, facts: &Value) -> Result<Option<crate::PolicyInference>> {
        let mut selected = None;
        for provider in self.providers.values() {
            if !provider.descriptor().actions.contains(&PolicyAction::Infer) {
                continue;
            }
            let Some(inferred) = provider.infer(source, facts)? else {
                continue;
            };
            ensure!(
                inferred.definition.id == provider.descriptor().id,
                "policy inference changed its registered identity"
            );
            self.prepare_definition(&inferred.definition)?;
            ensure!(
                selected.is_none(),
                "multiple installed policies infer the same Source value"
            );
            selected = Some(inferred);
        }
        Ok(selected)
    }
    pub fn compatible(&self, left: &PolicyDefinition, right: &PolicyDefinition) -> Result<bool> {
        if left.id != right.id || left.version != right.version {
            return Ok(false);
        }
        let left = self.prepare_definition(left)?;
        let options = serde_json::from_value(right.options.clone())?;
        left.implementation.compatible(&options)
    }
    pub fn register(&mut self, provider: Arc<dyn PolicyProvider>) -> Result<()> {
        let descriptor = provider.descriptor();
        PolicyDefinition {
            version: descriptor.version,
            ..PolicyDefinition::new(descriptor.id)
        }
        .validate()?;
        ensure!(
            !self.providers.contains_key(descriptor.id),
            "duplicate policy registration {:?}",
            descriptor.id
        );
        self.providers.insert(descriptor.id.into(), provider);
        Ok(())
    }
    pub fn descriptors(&self) -> impl Iterator<Item = PolicyDescriptor> + '_ {
        self.providers
            .values()
            .map(|provider| provider.descriptor())
    }
    pub fn supports(&self, id: &str, action: PolicyAction) -> bool {
        self.providers
            .get(id)
            .is_some_and(|provider| provider.descriptor().actions.contains(&action))
    }
    pub fn prepare(&self, id: &str, configuration: &Value) -> Result<PreparedPolicy> {
        let provider = self
            .providers
            .get(id)
            .with_context(|| format!("policy {id:?} is not installed"))?;
        ensure!(
            provider
                .descriptor()
                .actions
                .contains(&PolicyAction::Compare),
            "policy {id:?} has no comparison capability"
        );
        Ok(PreparedPolicy {
            descriptor: provider.descriptor(),
            implementation: provider.prepare(configuration)?,
        })
    }
    pub fn prepare_definition(&self, definition: &PolicyDefinition) -> Result<PreparedPolicy> {
        definition.validate()?;
        let options = serde_json::from_value(definition.options.clone())?;
        let prepared = self.prepare(&definition.id, &options)?;
        ensure!(
            prepared.descriptor().version == definition.version,
            "policy {:?} requires version {}, installed version is {}",
            definition.id,
            definition.version,
            prepared.descriptor().version
        );
        Ok(prepared)
    }
    pub fn prepare_transform(&self, id: &str, configuration: &Value) -> Result<PreparedTransform> {
        let provider = self
            .providers
            .get(id)
            .with_context(|| format!("policy {id:?} is not installed"))?;
        ensure!(
            provider
                .descriptor()
                .actions
                .contains(&PolicyAction::Transform),
            "policy {id:?} has no transformation capability"
        );
        Ok(PreparedTransform {
            descriptor: provider.descriptor(),
            implementation: provider.prepare_transform(configuration)?,
        })
    }
    pub fn prepare_transform_definition(
        &self,
        definition: &PolicyDefinition,
    ) -> Result<PreparedTransform> {
        definition.validate()?;
        let options = serde_json::from_value(definition.options.clone())?;
        let prepared = self.prepare_transform(&definition.id, &options)?;
        ensure!(
            prepared.descriptor().version == definition.version,
            "policy {:?} requires version {}, installed version is {}",
            definition.id,
            definition.version,
            prepared.descriptor().version,
        );
        Ok(prepared)
    }
    pub fn analyze(
        &self,
        input: &AnalysisInput<'_>,
        evidence: &dyn EvidenceAccess,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for provider in self.providers.values() {
            if !provider
                .descriptor()
                .actions
                .contains(&PolicyAction::Analyze)
            {
                continue;
            }
            let found = provider.analyze(input, evidence)?;
            ensure!(
                found
                    .iter()
                    .all(|finding| finding.policy == provider.descriptor().id),
                "policy analysis changed its registered identity"
            );
            findings.extend(found);
        }
        Ok(findings)
    }
}

#[derive(Clone)]
pub struct PreparedPolicy {
    descriptor: PolicyDescriptor,
    implementation: Arc<dyn ComparisonPolicy>,
}

pub struct PreparedTransform {
    descriptor: PolicyDescriptor,
    implementation: Arc<dyn TransformPolicy>,
}

impl PreparedTransform {
    pub fn descriptor(&self) -> &PolicyDescriptor {
        &self.descriptor
    }
    pub fn inspect(&self, input: &TransformInput<'_>) -> Result<Option<Box<dyn TransformPlan>>> {
        self.implementation.inspect(input)
    }
}
impl PreparedPolicy {
    pub fn validate_schema(&self, schema: &traffic_value::schema::FieldSchema) -> Result<()> {
        self.implementation.validate_schema(schema)
    }

    pub fn canonical_value(&self, value: &Value) -> Result<Option<Value>> {
        self.implementation.canonical_value(value)
    }
    pub fn entity_key(&self, source: &Value) -> Result<Option<[u8; 32]>> {
        self.implementation.entity_key(source)
    }
    pub fn applies(&self, source: &Value, facts: &Value) -> Result<bool> {
        self.implementation.applies(source, facts)
    }
    pub fn supports_child_rules(&self) -> bool {
        self.implementation.supports_child_rules()
    }
    pub fn descriptor(&self) -> &PolicyDescriptor {
        &self.descriptor
    }
    pub fn evaluate(
        &self,
        pair: &ValuePair<'_>,
        host: &mut dyn EvaluationHost,
    ) -> Result<Evaluation> {
        self.implementation.evaluate(pair, host)
    }
}
