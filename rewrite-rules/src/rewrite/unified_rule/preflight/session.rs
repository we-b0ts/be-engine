//! Source input verification freezes the original request and its signing inputs.
use super::*;
use crate::policy::{CompiledNativeRule, NativeEffect};

fn input_rule(rule: &CompiledNativeRule) -> bool {
    matches!(
        rule.rule.effect,
        NativeEffect::InputJwt(_) | NativeEffect::InputSignedTimestamp(_)
    )
}

struct Case {
    id: String,
    dir: std::path::PathBuf,
    request: Value,
}

pub fn verify(
    root: &Path,
    bundle: &mut Bundle,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
) -> Result<()> {
    if !policy
        .native
        .iter()
        .any(|rule| selected.contains(&rule.rule.id) && input_rule(rule))
    {
        return Ok(());
    }
    let mut cases = Vec::new();
    for (id, dir) in bundle.cases.clone() {
        let request = bundle.request(&dir.join("request.json"))?;
        cases.push(Case { id, dir, request });
    }
    let inputs = cases
        .iter()
        .map(|case| crate::policy::runtime::SourceInputCase {
            id: &case.id,
            dir: &case.dir,
            request: &case.request,
        })
        .collect::<Vec<_>>();
    let proof = crate::policy::runtime::validate_source_inputs(policy, selected, root, &inputs)?;
    for (path, digest) in &proof.key_witnesses {
        // Freeze actual private inputs by SHA256. The plan contains references
        // only; key values and raw startup files are never copied into reports.
        bundle.freeze(path)?;
        ensure!(
            bundle.artifacts[path].sha256 == *digest,
            "Source signing input changed between resolution and evidence freezing"
        );
    }
    for (id, count) in proof.rules.iter().filter(|(id, _)| selected.contains(*id)) {
        ensure!(
            *count > 0,
            "stateful Source rule {id:?} has no complete positive trace"
        );
        if !result.rules.contains_key(id) {
            result.source_validations += count;
        }
        result.rules.entry(id.clone()).or_insert(*count);
    }
    result.stateful_target_obligations.extend(
        policy
            .native
            .iter()
            .filter(|rule| selected.contains(&rule.rule.id) && input_rule(rule))
            .map(|rule| rule.rule.id.clone()),
    );
    Ok(())
}
