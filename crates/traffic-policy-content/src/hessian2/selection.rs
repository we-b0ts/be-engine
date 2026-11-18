use anyhow::Result;

use super::{
    Hessian2JoinedStringPath, Hessian2UnorderedPath, HessianValue, canonicalize_joined_string,
    canonicalize_path, parse_bodies,
};

pub fn selected_paths_match(
    policies: &traffic_policy::PolicyRegistry,
    expected: &[u8],
    actual: &[u8],
    effective_unordered: &[Hessian2UnorderedPath],
    effective_joined: &[Hessian2JoinedStringPath],
    selected_unordered: &[Hessian2UnorderedPath],
    selected_joined: &[Hessian2JoinedStringPath],
) -> Result<bool> {
    let (_, mut expected, mut actual) = parse_bodies(expected, actual)?;
    for rule in effective_unordered {
        canonicalize_path(&mut expected, &rule.value_path.0, &rule.value_path)?;
        canonicalize_path(&mut actual, &rule.value_path.0, &rule.value_path)?;
    }
    for rule in effective_joined {
        canonicalize_joined_string(policies, &mut expected, &rule.value_path.0, &rule.separator)?;
        canonicalize_joined_string(policies, &mut actual, &rule.value_path.0, &rule.separator)?;
    }

    Ok(selected_unordered
        .iter()
        .map(|rule| &rule.value_path.0)
        .chain(selected_joined.iter().map(|rule| &rule.value_path.0))
        .all(|path| selected_values(&expected, path) == selected_values(&actual, path)))
}

fn selected_values<'value, 'body>(
    value: &'value HessianValue<'body>,
    path: &[String],
) -> Vec<&'value HessianValue<'body>> {
    let Some((segment, remaining)) = path.split_first() else {
        return vec![value];
    };
    match value {
        HessianValue::Object { class, fields } => class
            .fields
            .iter()
            .zip(fields)
            .filter(|(name, _)| name.as_ref() == segment)
            .flat_map(|(_, value)| selected_values(value, remaining))
            .collect(),
        HessianValue::Map { entries, .. } => entries
            .iter()
            .filter_map(|(key, value)| {
                matches!(key, HessianValue::String(name) if name.as_ref() == segment)
                    .then_some(value)
            })
            .flat_map(|value| selected_values(value, remaining))
            .collect(),
        HessianValue::List { values, .. } if segment == "*" => values
            .iter()
            .flat_map(|value| selected_values(value, remaining))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {

    fn selected_paths_match(
        expected: &[u8],
        actual: &[u8],
        effective_unordered: &[Hessian2UnorderedPath],
        effective_joined: &[Hessian2JoinedStringPath],
        selected_unordered: &[Hessian2UnorderedPath],
        selected_joined: &[Hessian2JoinedStringPath],
    ) -> Result<bool> {
        super::selected_paths_match(
            traffic_extensions::policies(),
            expected,
            actual,
            effective_unordered,
            effective_joined,
            selected_unordered,
            selected_joined,
        )
    }

    use motan_hessian2::{ClassSchema, Encoder, Limits};

    use super::*;
    use traffic_policy_schema::response::Hessian2ValuePath;

    fn response(names: &[&str], source: &str) -> Vec<u8> {
        let mut body = Vec::new();
        let mut encoder = Encoder::new(&mut body, Limits::default());
        encoder
            .begin_object(ClassSchema::new("example.Response", &["names", "source"]))
            .unwrap();
        encoder.encode_value(&names.to_vec()).unwrap();
        encoder.encode_value(source).unwrap();
        encoder.end_object();
        body
    }

    fn names_rule() -> Hessian2UnorderedPath {
        Hessian2UnorderedPath {
            value_path: Hessian2ValuePath(vec!["names".to_string()]),
            display_path: "response.names".to_string(),
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
