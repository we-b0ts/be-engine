use anyhow::{Result, ensure};

use super::{
    ProtobufFieldPath, ProtobufJoinedStringPath, ProtobufUnorderedPath, canonicalize_rules,
    parse_bodies, parse_fields,
};

pub(in crate::replay) fn selected_paths_match(
    expected: &[u8],
    actual: &[u8],
    effective_unordered: &[ProtobufUnorderedPath],
    effective_joined: &[ProtobufJoinedStringPath],
    selected_unordered: &[ProtobufUnorderedPath],
    selected_joined: &[ProtobufJoinedStringPath],
) -> Result<bool> {
    let (_, expected, actual) = parse_bodies(expected, actual)?;
    let expected = canonicalize_rules(expected, effective_unordered, effective_joined)?;
    let actual = canonicalize_rules(actual, effective_unordered, effective_joined)?;

    selected_unordered
        .iter()
        .map(|rule| &rule.field_path)
        .chain(selected_joined.iter().map(|rule| &rule.field_path))
        .try_fold(true, |matches, path| {
            Ok(matches && select_groups(&expected, path)? == select_groups(&actual, path)?)
        })
}

fn select_groups<'a>(payload: &'a [u8], path: &ProtobufFieldPath) -> Result<Vec<Vec<&'a [u8]>>> {
    let mut groups = Vec::new();
    select_groups_inner(payload, &path.0, &mut groups)?;
    Ok(groups)
}

fn select_groups_inner<'a>(
    payload: &'a [u8],
    path: &[u32],
    groups: &mut Vec<Vec<&'a [u8]>>,
) -> Result<()> {
    let Some((number, remaining)) = path.split_first() else {
        return Ok(());
    };
    let fields = parse_fields(payload)?;
    let selected = fields
        .iter()
        .filter(|field| field.number == *number)
        .collect::<Vec<_>>();
    if remaining.is_empty() {
        groups.push(selected.into_iter().map(|field| field.raw).collect());
        return Ok(());
    }
    for field in selected {
        ensure!(
            field.wire_type == 2,
            "protobuf selected response-body path traverses a non-message field"
        );
        select_groups_inner(
            field
                .payload
                .expect("wire type 2 always carries a parsed payload"),
            remaining,
            groups,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::policy::ProtobufRepeatedElementType;

    fn response(names: &[&str], source: &str) -> Vec<u8> {
        let mut message = Vec::new();
        for name in names {
            message.push(0x1a);
            message.push(name.len() as u8);
            message.extend_from_slice(name.as_bytes());
        }
        message.push(0x22);
        message.push(source.len() as u8);
        message.extend_from_slice(source.as_bytes());
        message
    }

    fn names_rule() -> ProtobufUnorderedPath {
        ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![3]),
            display_path: "response.names".to_string(),
            element_type: ProtobufRepeatedElementType::String,
            source_evidence: "src/service.rs:42-48 names comes from a Set".to_string(),
        }
    }

    #[test]
    fn selected_path_ignores_residual_siblings_but_not_selected_content() {
        let rule = names_rule();
        let expected = response(&["alice", "bob"], "source-a");

        assert!(
            selected_paths_match(
                &expected,
                &response(&["bob", "alice"], "source-b"),
                std::slice::from_ref(&rule),
                &[],
                std::slice::from_ref(&rule),
                &[],
            )
            .unwrap()
        );
        assert!(
            !selected_paths_match(
                &expected,
                &response(&["bob", "zoe"], "source-b"),
                std::slice::from_ref(&rule),
                &[],
                std::slice::from_ref(&rule),
                &[],
            )
            .unwrap()
        );
    }
}
