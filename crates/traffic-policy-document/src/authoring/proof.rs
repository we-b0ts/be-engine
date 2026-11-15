//! Owner-local evidence inheritance; revision binding never inspects business literals.
use anyhow::{Context, Result, ensure};
use serde_yaml::{Mapping, Value};

pub fn revision(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 256
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:/@+-".contains(&b)),
        "source_revision must be a bounded explicit Source identity"
    );
    Ok(())
}

pub fn expand(raw: Option<Value>, parent: Option<&Value>, revision: Option<&str>) -> Result<Value> {
    if raw.is_none() && parent.is_none_or(Value::is_null) {
        return Ok(Value::Null);
    }
    expand_inner(raw, parent, revision, false)
}

pub fn expand_capture(raw: Option<Value>, revision: Option<&str>) -> Result<Value> {
    if raw.is_none() {
        return Ok(Value::Null);
    }
    expand_inner(raw, None, revision, true)
}

pub fn expand_inner(
    raw: Option<Value>,
    parent: Option<&Value>,
    revision: Option<&str>,
    source_optional: bool,
) -> Result<Value> {
    let mut result = parent
        .and_then(Value::as_mapping)
        .cloned()
        .unwrap_or_default();
    if let Some(raw) = raw {
        let raw = raw.as_mapping().context("proof requires source and fact")?;
        for (key, value) in raw {
            ensure!(
                matches!(key.as_str(), Some("source" | "fact")),
                "unknown proof field"
            );
            result.insert(key.clone(), value.clone());
        }
    }
    if let Some(source) = result.get_mut("source") {
        let source_text = crate::proof::deserialize_source(source.clone())?;
        *source = if source_optional && source_text.is_empty() {
            String::new()
        } else {
            let references = crate::proof::references(&source_text)?.join("; ");
            if let Some((_, revision)) = source_text.rsplit_once(" @ ") {
                format!("{references} @ {revision}")
            } else {
                references
            }
        }
        .into();
    } else if source_optional {
        result.insert("source".into(), "".into());
    }
    for key in ["source", "fact"] {
        ensure!(
            (key == "source" && source_optional)
                || result
                    .get(key)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.trim().is_empty()),
            "proof.{key} is required; proof inheritance stays within its owning rule or declaration subtree"
        );
    }
    if let Some(revision) = revision
        && !result["source"]
            .as_str()
            .expect("checked source")
            .is_empty()
    {
        let source = result["source"].as_str().expect("checked source");
        let source = if let Some((_, recorded)) = source.rsplit_once(" @ ") {
            ensure!(
                recorded == revision,
                "proof Source revision conflicts with document source_revision"
            );
            source.to_owned()
        } else {
            format!("{source} @ {revision}")
        };
        result.insert("source".into(), source.into());
    }
    Ok(Value::Mapping(result))
}

pub fn source_effect(map: &mut Mapping, revision: Option<&str>, compact: bool) -> Result<()> {
    let Some(revision) = revision else {
        return Ok(());
    };
    if let Some(existing) = map.get("source_revision") {
        ensure!(
            existing.as_str() == Some(revision),
            "effect Source revision conflicts with document source_revision"
        );
    } else if !compact {
        map.insert("source_revision".into(), revision.into());
    }
    if compact {
        map.remove("source_revision");
    }
    Ok(())
}
