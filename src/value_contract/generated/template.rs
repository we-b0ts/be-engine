//! Literal-preserving generated strings with automatic case-local token identities.
use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::policy::native::{Proven, TemplateToken};

type TemplateParts<'a> = (Vec<(&'a str, &'a str)>, &'a str);

fn parts(template: &str) -> Result<TemplateParts<'_>, GeneratedError> {
    if template.is_empty() || template.len() > 4096 {
        return Err(GeneratedError::InvalidShape);
    }
    let mut rest = template;
    let mut output = vec![];
    let mut names = BTreeSet::new();
    while let Some(start) = rest.find('{') {
        let literal = &rest[..start];
        if literal.contains('}') || !output.is_empty() && literal.is_empty() {
            return Err(GeneratedError::InvalidShape);
        }
        let tail = &rest[start + 1..];
        let end = tail.find('}').ok_or(GeneratedError::InvalidShape)?;
        let name = &tail[..end];
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || !names.insert(name)
        {
            return Err(GeneratedError::InvalidShape);
        }
        output.push((literal, name));
        if output.len() > 16 {
            return Err(GeneratedError::InvalidShape);
        }
        rest = &tail[end + 1..];
    }
    if rest.contains('}') || output.is_empty() {
        return Err(GeneratedError::InvalidShape);
    }
    Ok((output, rest))
}

pub(crate) fn validate_template(template: &str) -> anyhow::Result<BTreeSet<String>> {
    let (slots, _) = parts(template)
        .map_err(|_| anyhow::anyhow!("template requires bounded, unambiguous named slots"))?;
    Ok(slots.into_iter().map(|(_, name)| name.into()).collect())
}

fn extract<'a>(
    value: &'a str,
    template: &str,
) -> Result<BTreeMap<String, &'a str>, GeneratedError> {
    let (slots, suffix) = parts(template)?;
    if value.len() > 16 * 1024 {
        return Err(GeneratedError::InvalidShape);
    }
    let mut rest = value;
    let mut output = BTreeMap::new();
    for (index, (literal, name)) in slots.iter().enumerate() {
        rest = rest
            .strip_prefix(literal)
            .ok_or(GeneratedError::ContractMismatch)?;
        let delimiter = slots.get(index + 1).map_or(suffix, |(literal, _)| literal);
        let end = if delimiter.is_empty() {
            rest.len()
        } else {
            let mut offsets = rest.match_indices(delimiter);
            let (offset, _) = offsets.next().ok_or(GeneratedError::ContractMismatch)?;
            if offsets.next().is_some() {
                return Err(GeneratedError::InvalidShape);
            }
            offset
        };
        output.insert((*name).into(), &rest[..end]);
        rest = &rest[end..];
    }
    if rest != suffix {
        return Err(GeneratedError::ContractMismatch);
    }
    Ok(output)
}

pub(crate) fn valid_token(value: &str, token: &TemplateToken) -> bool {
    if random_value(value, &token.format, token.length).is_err() {
        return false;
    }
    token.decoded_bytes.is_none_or(|length| {
        let decoded = match token.format {
            RandomEncoding::Base64 => STANDARD.decode(value),
            RandomEncoding::Base64url => URL_SAFE_NO_PAD.decode(value),
            _ => return false,
        };
        decoded.is_ok_and(|bytes| bytes.len() == length)
    })
}

pub(super) fn compare(
    source: &str,
    target: &str,
    template: &str,
    fields: &BTreeMap<String, Proven<TemplateToken>>,
    rule_id: &str,
) -> Result<Comparison, GeneratedError> {
    let source = extract(source, template)?;
    let target = extract(target, template)?;
    if source.len() != fields.len() || target.len() != fields.len() {
        return Err(GeneratedError::ContractMismatch);
    }
    let mut result = evaluated(rule_id);
    for (name, field) in fields {
        let source = source.get(name).ok_or(GeneratedError::ContractMismatch)?;
        let target = target.get(name).ok_or(GeneratedError::ContractMismatch)?;
        for value in [source, target] {
            random_value(value, &field.contract.format, field.contract.length)?;
            if let Some(length) = field.contract.decoded_bytes {
                let decoded = match field.contract.format {
                    RandomEncoding::Base64 => STANDARD.decode(value),
                    RandomEncoding::Base64url => URL_SAFE_NO_PAD.decode(value),
                    _ => return Err(GeneratedError::InvalidShape),
                }
                .map_err(|_| GeneratedError::InvalidShape)?;
                if decoded.len() != length {
                    return Err(GeneratedError::InvalidShape);
                }
            }
        }
        if field.contract.length.is_none() && source.len() != target.len() {
            return Err(GeneratedError::InvalidShape);
        }
        result
            .identities
            .observe(
                &Value::String((*source).into()),
                &Value::String((*target).into()),
            )
            .map_err(|_| GeneratedError::ContractMismatch)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::native::GeneratedResponse;
    use serde_json::json;

    fn field(bytes: usize) -> Proven<TemplateToken> {
        super::super::tests::proof(TemplateToken {
            format: RandomEncoding::Base64url,
            decoded_bytes: Some(bytes),
            length: None,
        })
    }

    #[test]
    fn generated_url_keeps_host_path_query_and_automatic_session_identity() {
        let session = GeneratedResponse::Template {
            template: "vnc-{session}".into(),
            fields: BTreeMap::from([("session".into(), field(18))]),
        };
        let url = GeneratedResponse::Template {
            template: "wss://vnc.example/socket/{connection}?ticket={ticket}".into(),
            fields: BTreeMap::from([
                ("connection".into(), field(18)),
                ("ticket".into(), field(32)),
            ]),
        };
        let a = URL_SAFE_NO_PAD.encode([1u8; 18]);
        let b = URL_SAFE_NO_PAD.encode([2u8; 18]);
        let ticket = URL_SAFE_NO_PAD.encode([3u8; 32]);
        let source = json!({"session_id":format!("vnc-{a}"),"url":format!("wss://vnc.example/socket/{a}?ticket={ticket}")});
        let target = json!({"session_id":format!("vnc-{b}"),"url":format!("wss://vnc.example/socket/{b}?ticket={ticket}")});
        let native = [
            json::NativeField {
                rule_id: "vnc",
                pointer: "/session_id",
                contract: &session,
                key: None,
            },
            json::NativeField {
                rule_id: "link",
                pointer: "/url",
                contract: &url,
                key: None,
            },
        ];
        let compare = |target: &Value| {
            json::compare_with_native(&source, target, &[], &native, AnchorClocks::default())
        };
        assert!(compare(&target).passed());
        for value in [
            format!("wss://other.example/socket/{b}?ticket={ticket}"),
            format!("wss://vnc.example/other/{b}?ticket={ticket}"),
            format!("wss://vnc.example/socket/{b}?other={ticket}"),
            format!("wss://vnc.example/socket/{a}?ticket={ticket}"),
            format!("wss://vnc.example/socket/{b}=?ticket={ticket}"),
        ] {
            let mut changed = target.clone();
            changed["url"] = value.into();
            assert!(!compare(&changed).passed());
        }
        let mut changed = target;
        changed["session_id"] = format!("vnc-{b}=").into();
        assert!(!compare(&changed).passed());
    }

    #[test]
    fn template_admission_rejects_ambiguous_or_undeclared_slots() {
        for value in ["{a}{b}", "{a}-{a}", "{a", "a}", "literal"] {
            assert!(validate_template(value).is_err());
        }
    }
}
