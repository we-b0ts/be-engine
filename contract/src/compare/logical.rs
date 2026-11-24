//! Pair logical values with their compatibility projection for comparison.
use super::*;

pub struct LogicalProjection<'a> {
    logical: &'a traffic_value::Value,
    json: Value,
}

impl<'a> LogicalProjection<'a> {
    pub fn new(logical: &'a traffic_value::Value) -> serde_json::Result<Self> {
        Ok(Self {
            logical,
            json: serde_json::to_value(logical)?,
        })
    }

    pub fn json(&self) -> &Value {
        &self.json
    }
}

#[allow(clippy::too_many_arguments)] // Logical documents retain native verifiers and authenticated copy capabilities.
pub fn compare_logical_all(
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    copies: &[&dyn ValueCopyProof],
    metadata: &dyn RuleMetadata,
) -> Comparison {
    let Ok(source) = LogicalProjection::new(source) else {
        return invalid_projection();
    };
    compare_projected_logical_all(
        &source, target, fields, native, verified, clocks, copies, metadata,
    )
}

/// Compare using the same Source projection that the caller used to select fields.
#[allow(clippy::too_many_arguments)]
pub fn compare_projected_logical_all(
    source: &LogicalProjection<'_>,
    target: &traffic_value::Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
    copies: &[&dyn ValueCopyProof],
    metadata: &dyn RuleMetadata,
) -> Comparison {
    let target_projection = (!std::ptr::eq(source.logical, target))
        .then(|| serde_json::to_value(target))
        .transpose();
    let Ok(target_projection) = target_projection else {
        return invalid_projection();
    };
    compare_inputs(
        source.json(),
        target_projection.as_ref().unwrap_or(source.json()),
        fields,
        native,
        verified,
        clocks,
        copies,
        metadata,
        Some((source.logical, target)),
    )
}

fn invalid_projection() -> Comparison {
    Comparison {
        differences: vec![difference(
            "",
            "logical values cannot enter the compatibility projection",
        )],
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use traffic_value::Value as LogicalValue;

    #[test]
    fn projected_comparison_still_distinguishes_bytes_from_projected_arrays() {
        let mut source: LogicalValue = serde_json::from_value(json!({"a/~":[null]})).unwrap();
        *source.pointer_mut("/a~1~0/0").unwrap() = LogicalValue::Bytes(vec![1, 2]);
        let projection = LogicalProjection::new(&source).unwrap();
        let target = serde_json::from_value(projection.json().clone()).unwrap();
        let compared = compare_projected_logical_all(
            &projection,
            &target,
            &[],
            &[],
            &[],
            AnchorClocks::default(),
            &[],
            &ExplicitRules,
        );
        assert_eq!(compared.differences.len(), 1);
        assert_eq!(compared.differences[0].pointer, "/a~1~0/0");
    }

    #[test]
    fn unordered_pairs_keep_both_child_paths_during_structural_descent() {
        let source = serde_json::from_value(json!({"rows":[{"a/~":[1]}, {"a/~":[2]}]})).unwrap();
        let target = serde_json::from_value(json!({"rows":[{"a/~":[2]}, {"a/~":[1]}]})).unwrap();
        let fields = [
            Field {
                rule_id: "rows",
                pointer: "/rows",
                contract: &FieldContract::Unordered,
            },
            Field {
                rule_id: "nested-exact",
                pointer: "/rows/*/a~1~0/0",
                contract: &FieldContract::Exact,
            },
        ];
        let compared = compare_logical_all(
            &source,
            &target,
            &fields,
            &[],
            &[],
            AnchorClocks::default(),
            &[],
            &RegisteredRules(traffic_extensions::policies()),
        );
        assert!(compared.passed(), "{:?}", compared.differences);
        assert!(compared.evaluated.contains("nested-exact"));
    }
}
