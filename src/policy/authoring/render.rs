//! Readable authoring output; only small scalar maps/lists use YAML flow style.
use crate::policy::TrafficPolicy;
use anyhow::{Result, ensure};
use serde_yaml::Value;

pub fn render_policy(document: &TrafficPolicy) -> Result<String> {
    crate::policy::compile_policy(document)?;
    let value = super::document::compact_value(document)?;
    let mut output = String::new();
    emit(&value, 0, &mut output)?;
    let reparsed = crate::policy::parse_policy(&output)?;
    ensure!(
        crate::policy::compile_policy(document)? == crate::policy::compile_policy(&reparsed)?,
        "authoring renderer changed the expanded policy"
    );
    Ok(output)
}

fn scalar(value: &Value) -> Result<String> {
    Ok(serde_yaml::to_string(value)?.trim_end().to_owned())
}
fn flow_scalar(value: &Value) -> Result<String> {
    if let Some(text) = value.as_str()
        && text.contains([':', ',', '[', ']', '{', '}'])
    {
        return Ok(serde_json::to_string(text)?);
    }
    scalar(value)
}
fn atom(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    ) && !value.as_str().is_some_and(|s| s.contains(['\n', '\r']))
}
fn inline(value: &Value) -> Result<Option<String>> {
    let result = match value {
        Value::Mapping(map)
            if (map.len() <= 1
                || map.contains_key("relative_time")
                || map.contains_key("request_time"))
                && map.iter().all(|(k, v)| atom(k) && atom(v)) =>
        {
            let fields = map
                .iter()
                .map(|(k, v)| Ok(format!("{}: {}", flow_scalar(k)?, flow_scalar(v)?)))
                .collect::<Result<Vec<_>>>()?;
            format!("{{{}}}", fields.join(", "))
        }
        Value::Sequence(items) if items.len() <= 4 && items.iter().all(atom) => {
            let fields = items.iter().map(flow_scalar).collect::<Result<Vec<_>>>()?;
            format!("[{}]", fields.join(", "))
        }
        _ if atom(value) => return Ok(Some(scalar(value)?)),
        _ => return Ok(None),
    };
    Ok((result.len() <= 120).then_some(result))
}
fn emit(value: &Value, indent: usize, output: &mut String) -> Result<()> {
    let padding = " ".repeat(indent);
    if let Some(inline) = inline(value)? {
        output.push_str(&format!("{padding}{inline}\n"));
    } else {
        match value {
            Value::Mapping(map) => {
                for (key, value) in map {
                    let key = scalar(key)?;
                    if let Some(lines) = folded(value) {
                        output.push_str(&format!("{padding}{key}: >-\n"));
                        for line in lines {
                            output.push_str(&format!("{padding}  {line}\n"));
                        }
                    } else if let Some(inline) = inline(value)? {
                        output.push_str(&format!("{padding}{key}: {inline}\n"));
                    } else if atom(value) || value.is_string() {
                        let rendered = scalar(value)?;
                        let mut lines = rendered.lines();
                        output.push_str(&format!(
                            "{padding}{key}: {}\n",
                            lines.next().unwrap_or("null")
                        ));
                        for line in lines {
                            output.push_str(&format!("{padding}{line}\n"));
                        }
                    } else {
                        output.push_str(&format!("{padding}{key}:\n"));
                        emit(value, indent + 2, output)?;
                    }
                }
            }
            Value::Sequence(items) => {
                for item in items {
                    let mut rendered = String::new();
                    emit(item, indent + 2, &mut rendered)?;
                    output.push_str(&format!(
                        "{padding}- {}",
                        rendered
                            .strip_prefix(&" ".repeat(indent + 2))
                            .unwrap_or(&rendered)
                    ));
                }
            }
            _ => {
                for line in scalar(value)?.lines() {
                    output.push_str(&format!("{padding}{line}\n"));
                }
            }
        }
    }
    Ok(())
}

// Fold only ordinary single-space paragraphs. The render/parse identity check
// additionally protects exact proof text and significant whitespace.
fn folded(value: &Value) -> Option<Vec<String>> {
    let text = value.as_str()?;
    if text.chars().count() <= 100
        || text.trim() != text
        || text.contains("  ")
        || text.chars().any(|c| c.is_whitespace() && c != ' ')
    {
        return None;
    }
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split(' ') {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > 100 {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    (lines.len() > 1).then_some(lines)
}
