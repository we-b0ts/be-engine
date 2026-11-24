//! Traverse the shared prefixes of authored field selectors.
use std::{borrow::Cow, collections::BTreeMap, fmt::Write as _};

use anyhow::Result;

pub(super) trait SelectorValue: Sized {
    fn array(&self) -> Option<&[Self]>;
    fn member(&self, key: &str) -> Option<&Self>;
    fn members(&self) -> Option<impl ExactSizeIterator<Item = (&str, &Self)>>;
}

impl SelectorValue for serde_json::Value {
    fn array(&self) -> Option<&[Self]> {
        self.as_array().map(Vec::as_slice)
    }

    fn member(&self, key: &str) -> Option<&Self> {
        self.get(key)
    }

    fn members(&self) -> Option<impl ExactSizeIterator<Item = (&str, &Self)>> {
        self.as_object()
            .map(|values| values.iter().map(|(key, value)| (key.as_str(), value)))
    }
}

impl SelectorValue for traffic_value::Value {
    fn array(&self) -> Option<&[Self]> {
        self.as_array()
    }

    fn member(&self, key: &str) -> Option<&Self> {
        self.as_object()?.get(key)
    }

    fn members(&self) -> Option<impl ExactSizeIterator<Item = (&str, &Self)>> {
        self.as_object()
            .map(|values| values.iter().map(|(key, value)| (key.as_str(), value)))
    }
}

#[derive(Debug, Default)]
pub(super) struct SelectorTree {
    pattern: Option<Box<str>>,
    exact: BTreeMap<Box<str>, ExactBranch>,
    wildcard: Option<Box<WildcardBranch>>,
}

#[derive(Debug)]
struct ExactBranch {
    encoded: Box<str>,
    index: Option<usize>,
    tree: SelectorTree,
}

#[derive(Debug)]
struct WildcardBranch {
    prefix: Box<str>,
    tree: SelectorTree,
}

impl SelectorTree {
    pub(super) fn insert(&mut self, pattern: &str) {
        let mut tree = self;
        let mut start = 1;
        for segment in pattern.split('/').skip(1) {
            tree = if segment == "*" {
                &mut tree
                    .wildcard
                    .get_or_insert_with(|| {
                        Box::new(WildcardBranch {
                            prefix: pattern[..start - 1].into(),
                            tree: Self::default(),
                        })
                    })
                    .tree
            } else {
                let key = unescape(segment);
                &mut tree
                    .exact
                    .entry(key.into_owned().into_boxed_str())
                    .or_insert_with(|| ExactBranch {
                        encoded: segment.into(),
                        index: array_index(segment),
                        tree: Self::default(),
                    })
                    .tree
            };
            start += segment.len() + 1;
        }
        tree.pattern = Some(pattern.into());
    }

    pub(super) fn visit<'source, V: SelectorValue>(
        &self,
        source: &'source V,
        mut visitor: impl FnMut(&str, &str, &'source V) -> Result<()>,
    ) -> Result<()> {
        self.walk(source, &mut String::new(), &mut visitor)
    }

    fn walk<'source, V: SelectorValue>(
        &self,
        source: &'source V,
        path: &mut String,
        visitor: &mut impl FnMut(&str, &str, &'source V) -> Result<()>,
    ) -> Result<()> {
        if let Some(pattern) = &self.pattern {
            let pointer = if path.is_empty() {
                pattern.as_ref()
            } else {
                path.as_str()
            };
            visitor(pattern, pointer, source)?;
        }
        if self.exact.is_empty() && self.wildcard.is_none() {
            return Ok(());
        }
        if let Some(values) = source.array() {
            for branch in self.exact.values() {
                if let Some(value) = branch.index.and_then(|index| values.get(index)) {
                    branch.visit(value, path, visitor)?;
                }
            }
            if let Some(branch) = &self.wildcard {
                let prefix = path.len();
                if prefix == 0 {
                    path.push_str(&branch.prefix);
                }
                let array_prefix = path.len();
                for (index, value) in values.iter().enumerate() {
                    write!(path, "/{index}").expect("writing a String is infallible");
                    branch.tree.walk(value, path, visitor)?;
                    path.truncate(array_prefix);
                }
                path.truncate(prefix);
            }
        } else if let Some(members) = source.members() {
            if members.len() < self.exact.len() {
                for (key, value) in members {
                    if let Some(branch) = self.exact.get(key) {
                        branch.visit(value, path, visitor)?;
                    }
                }
            } else {
                for (key, branch) in &self.exact {
                    if let Some(value) = source.member(key) {
                        branch.visit(value, path, visitor)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl ExactBranch {
    fn visit<'source, V: SelectorValue>(
        &self,
        source: &'source V,
        path: &mut String,
        visitor: &mut impl FnMut(&str, &str, &'source V) -> Result<()>,
    ) -> Result<()> {
        let prefix = path.len();
        if prefix != 0 {
            path.push('/');
            path.push_str(&self.encoded);
        }
        self.tree.walk(source, path, visitor)?;
        path.truncate(prefix);
        Ok(())
    }
}

fn unescape(segment: &str) -> Cow<'_, str> {
    if segment.contains('~') {
        Cow::Owned(segment.replace("~1", "/").replace("~0", "~"))
    } else {
        Cow::Borrowed(segment)
    }
}

fn array_index(segment: &str) -> Option<usize> {
    if segment.starts_with('+') || (segment.starts_with('0') && segment != "0") {
        return None;
    }
    segment.parse().ok()
}

pub(super) fn pointer_pattern<V: SelectorValue>(source: &V, pointer: &str) -> String {
    let mut parent = Some(source);
    let mut pattern = String::with_capacity(pointer.len());
    for part in pointer.split('/').skip(1) {
        pattern.push('/');
        if let Some(array) = parent.and_then(SelectorValue::array) {
            pattern.push('*');
            parent = part
                .parse::<usize>()
                .ok()
                .and_then(|index| array.get(index));
        } else {
            pattern.push_str(part);
            parent = parent.and_then(|object| object.member(&unescape(part)));
        }
    }
    pattern
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn shared_prefixes_keep_each_selector_match_on_both_value_views() {
        let json = serde_json::json!({
            "items": [
                {"id": 1, "timestamp": 2, "a~/中": [[3, 4], [5]]},
                {"timestamp": 6, "a~/中": [[7]]}
            ],
            "object": {"*":[8], "01":9},
            "": null
        });
        let logical = traffic_value::Value::deserialize(&json).unwrap();
        let patterns = [
            "",
            "/",
            "/items",
            "/items/*/id",
            "/items/*/timestamp",
            "/items/*/a~0~1中/*/0",
            "/items/01/id",
            "/object/*/0",
            "/object/01",
        ];
        let mut tree = SelectorTree::default();
        let mut expected = BTreeMap::new();
        for pattern in patterns {
            tree.insert(pattern);
            let pointers = traffic_contract::delivery::select(pattern, &json).unwrap();
            if !pointers.is_empty() {
                expected.insert(pattern.to_owned(), pointers);
            }
        }
        assert_eq!(matches(&tree, &json), expected);
        assert_eq!(matches(&tree, &logical), expected);
    }

    fn matches<V: SelectorValue>(tree: &SelectorTree, source: &V) -> BTreeMap<String, Vec<String>> {
        let mut matches = BTreeMap::<_, Vec<_>>::new();
        tree.visit(source, |pattern, pointer, _| {
            matches
                .entry(pattern.to_owned())
                .or_default()
                .push(pointer.to_owned());
            Ok(())
        })
        .unwrap();
        matches
    }
}
