//! Resolve concrete field pointers once; wildcard matching retains Source shape guards.
use std::{borrow::Cow, collections::BTreeMap};

use serde_json::Value;

pub(super) struct Index<'a> {
    exact: BTreeMap<&'a str, Vec<usize>>,
    wildcard: Vec<(usize, &'a str)>,
}

impl<'a> Index<'a> {
    pub(super) fn new(pointers: impl Iterator<Item = &'a str>) -> Self {
        let mut exact = BTreeMap::<_, Vec<_>>::new();
        let mut wildcard = Vec::new();
        for (index, pointer) in pointers.enumerate() {
            if pointer.contains('*') {
                wildcard.push((index, pointer));
            } else {
                exact.entry(pointer).or_default().push(index);
            }
        }
        Self { exact, wildcard }
    }

    pub(super) fn matching(&self, pointer: &str, source: &Value) -> Cow<'_, [usize]> {
        let exact = self.exact.get(pointer).map_or(&[][..], Vec::as_slice);
        let mut wildcard = self.wildcard.iter().filter_map(|&(index, pattern)| {
            super::pointer_matches(pattern, pointer, source).then_some(index)
        });
        let Some(first) = wildcard.next() else {
            return Cow::Borrowed(exact);
        };
        // Conflicting and composed fields retain their authored order, even
        // when concrete pointers and wildcard patterns select the same node.
        let mut selected = exact.to_vec();
        selected.push(first);
        selected.extend(wildcard);
        selected.sort_unstable();
        Cow::Owned(selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn concrete_and_wildcard_fields_keep_source_shape_and_declaration_order() {
        let source = json!({"items":[{"id":1}],"object":{"0":{"id":2}},"*":3,"a/b":{"~":4}});
        let pointers = [
            "/items/*/id",
            "/items/0/id",
            "/object/*/id",
            "/items/*/id",
            "/*",
            "/a~1b/~0",
            "",
        ];
        let index = Index::new(pointers.into_iter());
        assert_eq!(&*index.matching("/items/0/id", &source), [0, 1, 3]);
        assert!(index.matching("/items/00/id", &source).is_empty());
        assert!(index.matching("/object/0/id", &source).is_empty());
        assert_eq!(&*index.matching("/*", &source), [4]);
        assert!(matches!(
            index.matching("/a~1b/~0", &source),
            Cow::Borrowed([5])
        ));
        assert_eq!(&*index.matching("", &source), [6]);
        assert!(index.matching("/missing", &source).is_empty());
    }

    #[test]
    fn many_concrete_fields_preserve_time_checks_and_the_exact_remainder() {
        use super::super::*;
        use crate::{
            compare::test_compare as compare,
            rule::{TimeRelation, TimestampFormat},
        };
        let source = json!({"blocks":(0..512).map(|_|json!({"timestamp":10,"text":"exact"})).collect::<Vec<_>>()});
        let mut target = source.clone();
        for block in target["blocks"].as_array_mut().unwrap() {
            block["timestamp"] = 110.into();
        }
        let pointers = (0..512)
            .map(|index| format!("/blocks/{index}/timestamp"))
            .collect::<Vec<_>>();
        let contract = FieldContract::Time {
            format: TimestampFormat::UnixSeconds,
            relation: TimeRelation::PreserveOffset,
            anchor: TimeAnchor::DependencyRequestStart,
            utc_offset: None,
            clock_group: None,
            clock_scope: Default::default(),
        };
        let fields = pointers
            .iter()
            .map(|pointer| Field {
                rule_id: "clock",
                pointer,
                contract: &contract,
            })
            .collect::<Vec<_>>();
        let clocks = AnchorClocks {
            dependency: ClockPair {
                source: chrono::DateTime::from_timestamp(10, 0),
                target: chrono::DateTime::from_timestamp(110, 0),
            },
            ..Default::default()
        };
        let result = compare(&source, &target, &fields, clocks);
        assert!(result.passed());
        assert_eq!(result.time_validations["clock"], 512);
        target["blocks"][400]["timestamp"] = 115.into();
        assert!(!compare(&source, &target, &fields, clocks).passed());
        target["blocks"][400]["timestamp"] = 110.into();
        target["blocks"][400]["text"] = "changed".into();
        assert!(!compare(&source, &target, &fields, clocks).passed());
    }
}
