use serde_json::Value;

pub fn body_diagnosis(facts: &Value) -> Option<&Value> {
    facts
        .pointer("/representative/response_difference/body_diagnosis")
        .or_else(|| facts.get("body_diagnosis"))
        .filter(|value| !value.is_null())
}

pub fn configured(facts: &Value) -> bool {
    body_diagnosis(facts)
        .and_then(|body| body.get("configured"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub fn codec_candidates(facts: &Value) -> Vec<&'static str> {
    let Some(body) = body_diagnosis(facts) else {
        return Vec::new();
    };
    if configured(facts) {
        return match body.get("codec").and_then(Value::as_str) {
            Some("protobuf") => vec!["protobuf"],
            Some("docx") => vec!["docx"],
            _ => Vec::new(),
        };
    }
    let candidates = body
        .get("codec_candidates")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    ["protobuf", "docx"]
        .into_iter()
        .filter(|supported| {
            candidates
                .iter()
                .any(|candidate| candidate.as_str() == Some(*supported))
        })
        .collect()
}
