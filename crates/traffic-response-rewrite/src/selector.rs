use anyhow::{Result, ensure};
use serde_json::Value;

#[derive(Debug)]
pub(super) struct Selector(Vec<String>);

impl Selector {
    pub(super) fn compile(path: &str) -> Result<Self> {
        ensure!(
            path.len() <= 4096 && (path.is_empty() || path.starts_with('/')),
            "response selector must be a bounded JSON pointer"
        );
        if path.is_empty() {
            return Ok(Self(Vec::new()));
        }
        let mut segments = Vec::new();
        for segment in path[1..].split('/') {
            let mut chars = segment.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' {
                    ensure!(
                        matches!(chars.next(), Some('0' | '1')),
                        "response selector has an invalid escape"
                    );
                }
            }
            segments.push(segment.replace("~1", "/").replace("~0", "~"));
        }
        ensure!(
            segments.len() <= 64,
            "response selector exceeds 64 segments"
        );
        Ok(Self(segments))
    }

    pub(super) fn select(&self, document: &Value) -> Result<Vec<String>> {
        let mut output = Vec::new();
        visit(document, &self.0, "", &mut output)?;
        Ok(output)
    }
}

fn visit(value: &Value, segments: &[String], path: &str, output: &mut Vec<String>) -> Result<()> {
    ensure!(
        output.len() <= 4096,
        "response selector exceeds 4096 locations"
    );
    let Some((segment, remainder)) = segments.split_first() else {
        output.push(path.into());
        return Ok(());
    };
    match value {
        Value::Array(values) if segment == "*" => {
            for (index, value) in values.iter().enumerate() {
                visit(value, remainder, &format!("{path}/{index}"), output)?;
            }
        }
        Value::Object(values) if segment == "*" => {
            for (key, value) in values {
                visit(value, remainder, &format!("{path}/{}", escape(key)), output)?;
            }
        }
        Value::Object(values) => {
            if let Some(value) = values.get(segment) {
                visit(
                    value,
                    remainder,
                    &format!("{path}/{}", escape(segment)),
                    output,
                )?;
            }
        }
        Value::Array(values) => {
            if let Ok(index) = segment.parse::<usize>()
                && index.to_string() == *segment
                && let Some(value) = values.get(index)
            {
                visit(value, remainder, &format!("{path}/{index}"), output)?;
            }
        }
        _ => (),
    }
    Ok(())
}

pub(super) fn escape(text: &str) -> String {
    text.replace('~', "~0").replace('/', "~1")
}
