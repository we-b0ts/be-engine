//! Bounded literal-preserving named slots shared by content policies.
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateError {
    InvalidShape,
    ContractMismatch,
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidShape => "invalid or ambiguous template shape",
            Self::ContractMismatch => "value differs from its template literals",
        })
    }
}
impl std::error::Error for TemplateError {}

type TemplateParts<'a> = (Vec<(&'a str, &'a str)>, &'a str);

fn parts(template: &str) -> Result<TemplateParts<'_>, TemplateError> {
    if template.is_empty() || template.len() > 4096 {
        return Err(TemplateError::InvalidShape);
    }
    let mut rest = template;
    let mut output = vec![];
    let mut names = BTreeSet::new();
    while let Some(start) = rest.find('{') {
        let literal = &rest[..start];
        if literal.contains('}') || !output.is_empty() && literal.is_empty() {
            return Err(TemplateError::InvalidShape);
        }
        let tail = &rest[start + 1..];
        let end = tail.find('}').ok_or(TemplateError::InvalidShape)?;
        let name = &tail[..end];
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || !names.insert(name)
        {
            return Err(TemplateError::InvalidShape);
        }
        output.push((literal, name));
        if output.len() > 16 {
            return Err(TemplateError::InvalidShape);
        }
        rest = &tail[end + 1..];
    }
    if rest.contains('}') || output.is_empty() {
        return Err(TemplateError::InvalidShape);
    }
    Ok((output, rest))
}

pub fn validate_template(template: &str) -> anyhow::Result<BTreeSet<String>> {
    let (slots, _) = parts(template)
        .map_err(|_| anyhow::anyhow!("template requires bounded, unambiguous named slots"))?;
    Ok(slots.into_iter().map(|(_, name)| name.into()).collect())
}

pub fn extract<'a>(
    value: &'a str,
    template: &str,
) -> Result<BTreeMap<String, &'a str>, TemplateError> {
    let (slots, suffix) = parts(template)?;
    if value.len() > 16 * 1024 {
        return Err(TemplateError::InvalidShape);
    }
    let mut rest = value;
    let mut output = BTreeMap::new();
    for (index, (literal, name)) in slots.iter().enumerate() {
        rest = rest
            .strip_prefix(literal)
            .ok_or(TemplateError::ContractMismatch)?;
        let delimiter = slots.get(index + 1).map_or(suffix, |(literal, _)| literal);
        let end = if delimiter.is_empty() {
            rest.len()
        } else {
            let mut offsets = rest.match_indices(delimiter);
            let (offset, _) = offsets.next().ok_or(TemplateError::ContractMismatch)?;
            if offsets.next().is_some() {
                return Err(TemplateError::InvalidShape);
            }
            offset
        };
        output.insert((*name).into(), &rest[..end]);
        rest = &rest[end..];
    }
    if rest != suffix {
        return Err(TemplateError::ContractMismatch);
    }
    Ok(output)
}
