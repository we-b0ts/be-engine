//! Bounded logical-location discovery delegated to an installed comparison policy.
use anyhow::{Result, ensure};
use traffic_policy::PreparedPolicy;
use traffic_value::Value;

const MAX_LOCATIONS: usize = 64;
const MAX_NODES: usize = 8192;
const MAX_DEPTH: usize = 32;

pub fn discover(
    policy: &PreparedPolicy,
    source: &Value,
    target: &Value,
    include_root: bool,
) -> Result<Vec<String>> {
    let mut found = Vec::new();
    let mut visited = 0;
    walk(
        policy,
        source,
        target,
        "",
        include_root,
        &mut found,
        &mut visited,
    )?;
    Ok(found)
}

fn walk(
    policy: &PreparedPolicy,
    source: &Value,
    target: &Value,
    pointer: &str,
    include_root: bool,
    found: &mut Vec<String>,
    visited: &mut usize,
) -> Result<()> {
    if source == target || found.len() >= MAX_LOCATIONS || pointer.matches('/').count() > MAX_DEPTH
    {
        return Ok(());
    }
    *visited += 1;
    ensure!(
        *visited <= MAX_NODES,
        "policy discovery exceeds its value budget"
    );
    if (include_root || !pointer.is_empty())
        && let (Some(left), Some(right)) = (
            policy.canonical_value(source)?,
            policy.canonical_value(target)?,
        )
        && left == right
    {
        found.push(pointer.into());
        return Ok(());
    }
    match (source, target) {
        (Value::Array(left), Value::Array(right)) if left.len() == right.len() => {
            for (index, (left, right)) in left.iter().zip(right).enumerate() {
                walk(
                    policy,
                    left,
                    right,
                    &format!("{pointer}/{index}"),
                    include_root,
                    found,
                    visited,
                )?;
            }
        }
        (Value::Object(left), Value::Object(right)) => {
            for (key, left) in left {
                if let Some(right) = right.get(key) {
                    let key = traffic_value::path::escape(key);
                    walk(
                        policy,
                        left,
                        right,
                        &format!("{pointer}/{key}"),
                        include_root,
                        found,
                        visited,
                    )?;
                }
            }
        }
        _ => (),
    }
    Ok(())
}

pub fn normalize(
    policy: &PreparedPolicy,
    source: &mut Value,
    target: &mut Value,
    pattern: &str,
) -> Result<bool> {
    traffic_value::path::validate(pattern, true)?;
    let mut selected = Vec::new();
    select(pattern, source, target, "", &mut selected)?;
    for pointer in selected {
        for value in [&mut *source, &mut *target] {
            if let Some(value) = value.pointer_mut(&pointer)
                && let Some(canonical) = policy.canonical_value(value)?
            {
                *value = canonical;
            }
        }
    }
    Ok(source == target)
}

fn select(
    remaining: &str,
    source: &Value,
    target: &Value,
    pointer: &str,
    selected: &mut Vec<String>,
) -> Result<()> {
    ensure!(
        selected.len() < MAX_NODES,
        "policy selection exceeds its value budget"
    );
    if remaining.is_empty() {
        selected.push(pointer.into());
        return Ok(());
    }
    let end = remaining[1..]
        .find('/')
        .map_or(remaining.len(), |index| index + 1);
    let segment = &remaining[1..end];
    let tail = &remaining[end..];
    if segment == "*"
        && let (Value::Array(left), Value::Array(right)) = (source, target)
    {
        for (index, (left, right)) in left.iter().zip(right).enumerate() {
            select(tail, left, right, &format!("{pointer}/{index}"), selected)?;
        }
    } else {
        let child = format!("/{segment}");
        if let (Some(left), Some(right)) = (source.pointer(&child), target.pointer(&child)) {
            select(tail, left, right, &format!("{pointer}{child}"), selected)?;
        }
    }
    Ok(())
}

pub mod bodies;

pub mod analysis;
pub mod message;
