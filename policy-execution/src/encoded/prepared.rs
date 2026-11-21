//! Bounded immutable codec-group preparation. No observation, decision or clock is cached.
use super::*;
use std::{cell::RefCell, collections::VecDeque};

const MAX_GROUPS: usize = 64;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_INPUTS: usize = 256;
struct Group {
    key: Vec<usize>,
    provider: traffic_value::codec::CodecIdentity,
    // Owning every identity prevents allocator-address reuse from producing a hit.
    _inputs: Vec<Arc<CodecPlan>>,
    plan: Arc<CodecPlan>,
    bytes: usize,
}
#[derive(Default)]
struct Cache {
    groups: VecDeque<Group>,
    bytes: usize,
}
thread_local! { static CACHE: RefCell<Cache> = RefCell::new(Cache::default()); }

pub(super) fn codec<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    rules: &[&R],
) -> Result<Arc<CodecPlan>> {
    let first = rules
        .first()
        .context("value comparison requires selected rules")?;
    if rules
        .iter()
        .all(|rule| rule.binding().codec == first.binding().codec)
    {
        return Ok(Arc::clone(first.binding().codec_plan));
    }
    let mut key = rules
        .iter()
        .map(|rule| Arc::as_ptr(rule.binding().codec_plan) as usize)
        .collect::<Vec<_>>();
    key.sort_unstable();
    key.dedup();
    let provider = context
        .codecs
        .installation_identity(first.binding().codec.id())
        .context("selected codec is not installed")?;
    if let Some(plan) = CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let position = cache
            .groups
            .iter()
            .position(|entry| entry.key == key && entry.provider == provider)?;
        let group = cache.groups.remove(position)?;
        let plan = group.plan.clone();
        cache.groups.push_back(group);
        Some(plan)
    }) {
        return Ok(plan);
    }
    let merged = merged_codec(context, rules)?;
    let plan = Arc::new(CodecPlan::compile(&merged, context.codecs)?);
    let mut unique = std::collections::BTreeMap::new();
    for rule in rules {
        unique
            .entry(Arc::as_ptr(rule.binding().codec_plan) as usize)
            .or_insert(*rule);
    }
    let bytes = estimated_bytes(&merged)
        + unique
            .values()
            .map(|rule| estimated_bytes(rule.binding().codec))
            .sum::<usize>()
        + key.len() * (std::mem::size_of::<usize>() + std::mem::size_of::<Arc<CodecPlan>>())
        + std::mem::size_of::<traffic_value::codec::CodecIdentity>();
    if key.len() <= MAX_INPUTS && bytes <= MAX_BYTES {
        let inputs = unique
            .values()
            .map(|rule| rule.binding().codec_plan.clone())
            .collect();
        CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            while cache.groups.len() >= MAX_GROUPS || cache.bytes + bytes > MAX_BYTES {
                let Some(evicted) = cache.groups.pop_front() else {
                    break;
                };
                cache.bytes -= evicted.bytes;
            }
            cache.bytes += bytes;
            cache.groups.push_back(Group {
                key,
                provider,
                _inputs: inputs,
                plan: plan.clone(),
                bytes,
            });
        });
    }
    Ok(plan)
}
#[cfg(any(test, feature = "test-support"))]
pub fn clear() {
    CACHE.with(|cache| *cache.borrow_mut() = Cache::default());
}

fn estimated_bytes(codec: &Codec) -> usize {
    serde_json::to_vec(codec.configuration()).map_or(MAX_BYTES + 1, |configuration| {
        configuration.len().saturating_mul(128)
    })
}

#[cfg(any(test, feature = "test-support"))]
pub fn occupancy() -> (usize, usize) {
    CACHE.with(|cache| {
        let cache = cache.borrow();
        (cache.groups.len(), cache.bytes)
    })
}
