//! Only independently reconstructed engine deliveries may rename fixed inputs.
use super::*;
use crate::value_contract::identities::{IdentityDecision, IdentityPair};

#[derive(Clone)]
pub(super) enum InputOrigin {
    Policy(PathBuf),
    Root(PathBuf),
}

pub(super) struct AuthorizedInputs {
    pairs: BTreeMap<String, String>,
}

pub(crate) struct PreparedDerivedInputs {
    case: String,
    begun_at: DateTime<Utc>,
    sent_at: DateTime<Utc>,
    pairs: Vec<IdentityPair>,
    // Retain immutable startup snapshots through the final admission.
    runtime: crate::request_rules::RequestRuleRuntime,
}

impl RequestContracts {
    pub(crate) fn prepare_derived_inputs(
        &self,
        case: &str,
        sent_at: DateTime<Utc>,
        actual: &Value,
    ) -> Result<PreparedDerivedInputs> {
        let anchor = self.anchor(case)?;
        let begun_at = anchor
            .actual
            .context("derived input requires request_begin")?;
        ensure!(
            sent_at >= begun_at && sent_at <= Utc::now(),
            "derived input send clock is outside its active request"
        );
        let path = anchor.dir.join("request.json");
        let raw = std::fs::read(&path)?;
        ensure!(
            self.state
                .lock()
                .expect("request contracts")
                .source_request_digests
                .get(case)
                == Some(&crate::policy_evidence::digest(&raw)),
            "immutable Source input changed after replay loading"
        );
        let source: Value =
            serde_json::from_slice(&crate::request_headers::load_request_file(&path)?)?;
        let root = match self
            .input_origin
            .as_ref()
            .context("input reconstruction origin unavailable")?
        {
            InputOrigin::Root(root) => root.clone(),
            InputOrigin::Policy(policy) => crate::config::resolve_unified_policy_root(policy)?,
        };
        let compiled = self
            .compiled_rules()
            .context("derived input requires its compiled policy")?;
        let mut runtime = crate::request_rules::RequestRuleRuntime::from_compiled(&root, compiled)?;
        runtime.freeze_for_request(&source)?;
        let mut expected = source.clone();
        runtime.apply(&mut expected, sent_at)?;
        ensure!(
            expected == *actual,
            "delivered input differs from independently reconstructed native input"
        );
        let mut pairs = runtime.derived_identity_pairs(&source, &expected)?;
        let changed = pairs
            .iter()
            .map(|pair| pair.source.clone())
            .collect::<BTreeSet<_>>();
        let before = input_scalars(&source)?;
        let after = input_scalars(&expected)?;
        ensure!(
            before.len() == after.len(),
            "native input changed scalar positions"
        );
        for (source, target) in before.into_iter().zip(after) {
            let Ok(source) = crate::value_contract::json::identity_key(&source, "") else {
                continue;
            };
            if changed.contains(&source) {
                let target = crate::value_contract::json::identity_key(&target, "")
                    .map_err(|difference| anyhow::anyhow!(difference.reason))?;
                pairs.push(IdentityPair { source, target });
            }
        }
        // This catches an untransformed duplicate of a re-signed token before
        // either occurrence is exposed to Target.
        let decision = IdentityDecision::prepare(case, pairs.clone())?;
        self.values
            .identities
            .lock()
            .expect("identity contracts")
            .validate(&decision)?;
        Ok(PreparedDerivedInputs {
            case: case.into(),
            begun_at,
            sent_at,
            pairs,
            runtime,
        })
    }

    pub(crate) fn commit_derived_inputs(&self, prepared: PreparedDerivedInputs) -> Result<()> {
        prepared.runtime.ensure_frozen_inputs_current()?;
        let mut state = self.state.lock().expect("request contracts");
        ensure!(
            state.cases.get(&prepared.case).and_then(|case| case.actual) == Some(prepared.begun_at)
                && !state.derived_inputs.contains_key(&prepared.case),
            "derived input belongs to a different request admission"
        );
        let decision = IdentityDecision::prepare(&prepared.case, prepared.pairs.clone())?;
        self.values
            .identities
            .lock()
            .expect("identity contracts")
            .commit(decision)?;
        state.derived_inputs.insert(
            prepared.case.clone(),
            AuthorizedInputs {
                pairs: prepared
                    .pairs
                    .into_iter()
                    .map(|pair| (pair.source, pair.target))
                    .collect(),
            },
        );
        state
            .cases
            .get_mut(&prepared.case)
            .expect("checked case")
            .actual = Some(prepared.sent_at);
        Ok(())
    }

    pub(super) fn derived_input_pair_is_authorized(&self, case: &str, pair: &IdentityPair) -> bool {
        self.state
            .lock()
            .expect("request contracts")
            .derived_inputs
            .get(case)
            .and_then(|inputs| inputs.pairs.get(&pair.source))
            .is_some_and(|target| target == &pair.target)
    }
}

/// Stable scalar positions of the URI and JSON body, matching the fixed-input
/// index. Header JWTs are already explicit native token locations above.
fn input_scalars(request: &Value) -> Result<Vec<Value>> {
    let mut values = Vec::new();
    let uri = request["uri"]
        .as_str()
        .context("input URI unavailable")?
        .parse::<hyper::Uri>()?;
    for segment in uri.path().split('/').filter(|segment| !segment.is_empty()) {
        values.push(Value::String(super::identity_inputs::decode_path_segment(
            segment,
        )?));
    }
    for (_, value) in ::url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()) {
        values.push(Value::String(value.into_owned()));
    }
    if let Some(body) = unified::source_body(request) {
        flatten(&body, &mut values, 0)?;
    }
    ensure!(
        values.len() <= 16384
            && values
                .iter()
                .map(|value| value.to_string().len())
                .sum::<usize>()
                <= 1024 * 1024,
        "derived input index exceeds bounds"
    );
    Ok(values)
}
fn flatten(value: &Value, values: &mut Vec<Value>, depth: usize) -> Result<()> {
    ensure!(
        depth <= 128 && values.len() <= 16384,
        "derived input index exceeds bounds"
    );
    match value {
        Value::Array(items) => {
            for item in items {
                flatten(item, values, depth + 1)?;
            }
        }
        Value::Object(items) => {
            for item in items.values() {
                flatten(item, values, depth + 1)?;
            }
        }
        _ => values.push(value.clone()),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
