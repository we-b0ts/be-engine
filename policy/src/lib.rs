//! Registered value semantics and evidence analysis, independent of execution stages.
use anyhow::Result;
use std::sync::Arc;
use traffic_value::Value;

mod definition;
mod observations;
mod registry;
mod scope;
pub use definition::PolicyDefinition;
pub use observations::{ObservationState, Observations};
pub use registry::{PolicyRegistry, PreparedPolicy, PreparedPolicySelection, PreparedTransform};
pub use scope::{ScopeKey, ValueScope};
mod transform;
pub use transform::{
    ResourceRequest, TransformInput, TransformPlan, TransformPolicy, TransformedValue,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Compare,
    Transform,
    Analyze,
    Infer,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyDescriptor {
    pub id: &'static str,
    pub version: u32,
    pub description: &'static str,
    pub actions: &'static [PolicyAction],
}

pub struct ValuePair<'a> {
    pub source: &'a Value,
    pub target: &'a Value,
    pub source_path: &'a str,
    pub target_path: &'a str,
}

#[derive(Debug, Clone)]
pub struct Difference {
    pub source_path: String,
    pub target_path: String,
    pub code: String,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationStatus {
    Matched,
    Mismatched,
    Incomplete,
}

#[derive(Debug, Clone)]
pub struct Evaluation {
    pub status: EvaluationStatus,
    pub differences: Vec<Difference>,
    pub counts: std::collections::BTreeMap<String, usize>,
}

impl Evaluation {
    pub fn matched() -> Self {
        Self {
            status: EvaluationStatus::Matched,
            differences: Vec::new(),
            counts: Default::default(),
        }
    }
    pub fn mismatch(pair: &ValuePair<'_>, code: &str, summary: &str) -> Self {
        Self {
            status: EvaluationStatus::Mismatched,
            differences: vec![Difference {
                source_path: pair.source_path.into(),
                target_path: pair.target_path.into(),
                code: code.into(),
                summary: summary.into(),
            }],
            counts: Default::default(),
        }
    }
    pub fn passed(&self) -> bool {
        self.status == EvaluationStatus::Matched && self.differences.is_empty()
    }
    pub fn with_count(mut self, name: &str, count: usize) -> Self {
        self.counts.insert(name.into(), count);
        self
    }
}

/// Composite strategies compare child locations through a transactional host.
/// Checkpoints isolate speculative relationships until one branch is accepted.
pub trait EvaluationHost {
    fn relate(&mut self, _pair: &ValuePair<'_>) -> Result<()> {
        anyhow::bail!("value correspondence storage is unavailable")
    }
    fn observe(&mut self, _state: Box<dyn ObservationState>) -> Result<()> {
        anyhow::bail!("policy observation storage is unavailable")
    }
    fn scope(&mut self, _scope: &ValueScope) -> Result<ScopeKey> {
        anyhow::bail!("value scope resolution is unavailable")
    }
    fn permits_copy(&self, _requirement: &Value) -> Result<bool> {
        Ok(false)
    }
    fn facts(&self) -> Result<Value> {
        Ok(Value::Null)
    }
    fn has_descendant_rules(&self) -> bool {
        false
    }
    fn checkpoint(&mut self) -> Result<u64> {
        anyhow::bail!("policy checkpoints are unavailable")
    }
    fn rollback(&mut self, _checkpoint: u64) -> Result<()> {
        anyhow::bail!("policy checkpoints are unavailable")
    }
    fn accept(&mut self, _checkpoint: u64) -> Result<()> {
        anyhow::bail!("policy checkpoints are unavailable")
    }
    fn compare(&mut self, _source_path: &str, _target_path: &str) -> Result<Evaluation> {
        anyhow::bail!("policy child comparison is unavailable")
    }
    fn budget_remaining(&self) -> bool {
        true
    }
}

impl EvaluationHost for () {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMatch {
    Inapplicable,
    Applicable,
    Ranked(Option<u128>),
}

pub trait ComparisonPolicy: Send + Sync {
    fn validate_schema(&self, _schema: &traffic_value::schema::FieldSchema) -> Result<()> {
        Ok(())
    }

    fn source_match(&self, source: &Value, facts: &Value) -> Result<SourceMatch> {
        Ok(if self.applies(source, facts)? {
            SourceMatch::Applicable
        } else {
            SourceMatch::Inapplicable
        })
    }
    /// An optional representative of this policy's equality class for diagnostics.
    fn canonical_value(&self, _value: &Value) -> Result<Option<Value>> {
        Ok(None)
    }
    fn entity_key(&self, _source: &Value) -> Result<Option<[u8; 32]>> {
        Ok(None)
    }
    fn compatible(&self, _other_configuration: &Value) -> Result<bool> {
        Ok(false)
    }
    fn applies(&self, _source: &Value, _facts: &Value) -> Result<bool> {
        Ok(true)
    }
    fn supports_child_rules(&self) -> bool {
        false
    }
    fn evaluate(&self, pair: &ValuePair<'_>, host: &mut dyn EvaluationHost) -> Result<Evaluation>;
}

pub struct AnalysisInput<'a> {
    pub values: Option<ValuePair<'a>>,
    pub facts: &'a Value,
}

/// Source-selected semantics supplied by an installed implementation.
pub struct PolicyInference {
    pub rule_id: &'static str,
    pub definition: PolicyDefinition,
    pub declaration: Option<Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "placement", content = "value", rename_all = "snake_case")]
pub enum Proposal {
    Field(Value),
    Document(Value),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub policy: String,
    pub source_path: String,
    pub summary: String,
    pub hint: String,
    pub proposal: Option<Proposal>,
    pub requirements: Vec<String>,
}

pub trait EvidenceAccess {
    fn query(&self, kind: &str, selection: &Value) -> Result<Vec<Value>>;
}

pub trait PolicyProvider: Send + Sync {
    fn descriptor(&self) -> PolicyDescriptor;
    fn infer(&self, _source: &Value, _facts: &Value) -> Result<Option<PolicyInference>> {
        Ok(None)
    }
    fn prepare(&self, _configuration: &Value) -> Result<Arc<dyn ComparisonPolicy>> {
        anyhow::bail!("policy has no comparison capability")
    }
    fn prepare_transform(&self, _configuration: &Value) -> Result<Arc<dyn TransformPolicy>> {
        anyhow::bail!("policy has no transformation capability")
    }
    fn analyze(
        &self,
        _input: &AnalysisInput<'_>,
        _evidence: &dyn EvidenceAccess,
    ) -> Result<Vec<Finding>> {
        Ok(Vec::new())
    }
}
