//! Bounded immutable codec-group preparation. No observation, decision or clock is cached.
use super::*;
use std::{cell::RefCell, collections::VecDeque};

const MAX_GROUPS: usize = 64;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_INPUTS: usize = 256;
struct Group {
    key: Vec<usize>,
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

pub(super) fn codec(rules: &[&CompiledRule]) -> Result<Arc<CodecPlan>> {
    let first = rules
        .first()
        .context("value comparison requires selected rules")?;
    if rules.iter().all(|rule| rule.rule.codec == first.rule.codec) {
        return Ok(Arc::clone(&first.codec_plan));
    }
    let mut key = rules
        .iter()
        .map(|rule| Arc::as_ptr(&rule.codec_plan) as usize)
        .collect::<Vec<_>>();
    key.sort_unstable();
    key.dedup();
    if let Some(plan) = CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let position = cache.groups.iter().position(|entry| entry.key == key)?;
        let group = cache.groups.remove(position)?;
        let plan = group.plan.clone();
        cache.groups.push_back(group);
        Some(plan)
    }) {
        return Ok(plan);
    }
    let merged = merged_codec(rules)?;
    let plan = Arc::new(CodecPlan::compile(&merged)?);
    let mut unique = std::collections::BTreeMap::new();
    for rule in rules {
        unique
            .entry(Arc::as_ptr(&rule.codec_plan) as usize)
            .or_insert(*rule);
    }
    let bytes = estimated_bytes(&merged)
        + unique
            .values()
            .map(|rule| estimated_bytes(&rule.rule.codec))
            .sum::<usize>()
        + key.len() * (std::mem::size_of::<usize>() + std::mem::size_of::<Arc<CodecPlan>>());
    if key.len() <= MAX_INPUTS && bytes <= MAX_BYTES {
        let inputs = unique
            .values()
            .map(|rule| rule.codec_plan.clone())
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
                _inputs: inputs,
                plan: plan.clone(),
                bytes,
            });
        });
    }
    Ok(plan)
}
#[cfg(test)]
pub(super) fn clear() {
    CACHE.with(|cache| *cache.borrow_mut() = Cache::default());
}

fn estimated_bytes(codec: &Codec) -> usize {
    match codec {
        Codec::Protobuf(codec) => codec
            .fields
            .iter()
            .map(|(alias, field)| alias.len() + field.field_path.len() * 128 + 256)
            .sum(),
        Codec::Json | Codec::Scalar => 0,
    }
}
#[cfg(test)]
pub(super) fn occupancy() -> (usize, usize) {
    CACHE.with(|cache| {
        let cache = cache.borrow();
        (cache.groups.len(), cache.bytes)
    })
}
