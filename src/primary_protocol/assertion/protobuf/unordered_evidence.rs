//! Typed order witnesses reusable by dependency value discovery, including packed fields.
use super::*;
const MAX_VISITED_FIELDS: usize = 4096;

pub(crate) fn candidates(
    expected: &[u8],
    actual: &[u8],
) -> Vec<(ProtobufFieldPath, Vec<ProtobufRepeatedElementType>)> {
    let Ok((_, source, _)) = parse_bodies(expected, actual) else {
        return Vec::new();
    };
    let mut paths = BTreeSet::new();
    let mut budget = MAX_VISITED_FIELDS;
    if !collect_paths(source, &[], &mut paths, &mut budget) {
        return Vec::new();
    }
    use ProtobufRepeatedElementType::*;
    let types = [
        String, Message, Int32, Int64, Uint32, Uint64, Sint32, Sint64, Bool, Enum, Fixed32,
        Sfixed32, Float, Fixed64, Sfixed64, Double,
    ];
    let mut candidates: Vec<(ProtobufFieldPath, Vec<ProtobufRepeatedElementType>)> = Vec::new();
    for field_path in paths {
        let probe = rule(&field_path, types[0]);
        if selected_paths_match(
            expected,
            actual,
            &[],
            &[],
            std::slice::from_ref(&probe),
            &[],
        )
        .unwrap_or(false)
        {
            continue;
        }
        let valid = types
            .into_iter()
            .filter(|element_type| {
                let rule = rule(&field_path, *element_type);
                selected_paths_match(
                    expected,
                    actual,
                    std::slice::from_ref(&rule),
                    &[],
                    std::slice::from_ref(&rule),
                    &[],
                )
                .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        if !valid.is_empty() {
            candidates.push((field_path, valid));
        }
    }
    let rules = candidates
        .iter()
        .filter(|(path, _)| {
            !candidates
                .iter()
                .any(|(other, _)| other != path && other.0.starts_with(&path.0))
        })
        .map(|(path, types)| rule(path, types[0]))
        .collect::<Vec<_>>();
    // Selected-field witnesses are insufficient: all residual fields must also match.
    if compare_protobuf(expected, actual, &rules, &[]).unwrap_or(false) {
        candidates
    } else {
        Vec::new()
    }
}
fn rule(
    path: &ProtobufFieldPath,
    element_type: ProtobufRepeatedElementType,
) -> ProtobufUnorderedPath {
    ProtobufUnorderedPath {
        field_path: path.clone(),
        display_path: "value.collection".into(),
        element_type,
        source_evidence: String::new(),
    }
}
fn collect_paths(
    body: &[u8],
    prefix: &[u32],
    paths: &mut BTreeSet<ProtobufFieldPath>,
    budget: &mut usize,
) -> bool {
    if prefix.len() >= MAX_NESTING_DEPTH {
        return true;
    }
    let Ok(fields) = parse_fields(body) else {
        return true;
    };
    for field in fields {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        let mut path = prefix.to_vec();
        path.push(field.number);
        paths.insert(ProtobufFieldPath(path.clone()));
        if paths.len() > MAX_DISCOVERED_PATHS {
            return false;
        }
        if let Some(payload) = field.payload
            && !collect_paths(payload, &path, paths, budget)
        {
            return false;
        }
    }
    true
}
