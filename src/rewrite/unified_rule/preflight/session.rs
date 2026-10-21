//! Stateful Source traces use isolated domain state, never invented Target pairs.
use super::*;
use crate::policy::{CompiledNativeRule, NativeEffect};

fn stateful(rule: &CompiledNativeRule) -> bool {
    match &rule.rule.effect {
        NativeEffect::Identity(_)
        | NativeEffect::RedisSequence(_)
        | NativeEffect::RedisAppendStream
        | NativeEffect::RedisReadCommutation(_)
        | NativeEffect::RedisExpiryRefresh(_)
        | NativeEffect::RedisLock
        | NativeEffect::RedisPublishIdentity(_)
        | NativeEffect::HttpRequest(_)
        | NativeEffect::InputJwt(_)
        | NativeEffect::InputSignedTimestamp(_) => true,
        NativeEffect::MysqlValues(effect) => {
            !effect.params.is_empty() || !effect.response_time.is_empty()
        }
        _ => false,
    }
}

struct Case {
    id: String,
    dir: std::path::PathBuf,
    request: Value,
    events: Vec<Value>,
}

pub(super) fn verify(
    root: &Path,
    bundle: &mut Bundle,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
) -> Result<()> {
    if !policy
        .native
        .iter()
        .any(|rule| selected.contains(&rule.rule.id) && stateful(rule))
    {
        return Ok(());
    }
    let mut cases = Vec::new();
    let mut total = 0usize;
    for (id, dir) in bundle.cases.clone() {
        let request = bundle.request(&dir.join("request.json"))?;
        let path = dir.join("dependencies.jsonl");
        bundle.freeze(&path)?;
        let bytes = fs::read(&path)?;
        total = total
            .checked_add(bytes.len())
            .context("Source trace inventory size overflow")?;
        ensure!(
            total <= 1024 * 1024 * 1024,
            "Source trace inventory exceeds supported evidence bounds"
        );
        ensure!(
            crate::policy_evidence::digest(&bytes) == bundle.artifacts[&path].sha256,
            "Source dependency trace changed while loading"
        );
        let events = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            .map(|line| {
                ensure!(
                    line.len() <= crate::dependency::http_limits::MAX_RECORD_BYTES,
                    "Source exchange exceeds supported evidence bounds"
                );
                serde_json::from_slice(line).context("invalid immutable Source dependency exchange")
            })
            .collect::<Result<Vec<Value>>>()?;
        cases.push(Case {
            id,
            dir,
            request,
            events,
        });
    }
    let inputs = cases
        .iter()
        .map(|case| crate::replay::NativeSourceCase {
            id: &case.id,
            dir: &case.dir,
            request: &case.request,
            events: &case.events,
        })
        .collect::<Vec<_>>();
    let proof =
        crate::replay::validate_native_source_dependencies(policy, selected, root, &inputs)?;
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
            .filter(|rule| selected.contains(&rule.rule.id) && stateful(rule))
            .map(|rule| rule.rule.id.clone()),
    );
    Ok(())
}
