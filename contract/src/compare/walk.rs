//! Typed child lookup and reusable diagnostic paths for structural descent.
use std::fmt::Write;

use serde_json::Value;
use traffic_value::Value as LogicalValue;

#[derive(Clone, Copy)]
pub(super) struct Node<'a> {
    pub projected: &'a Value,
    pub logical: Option<&'a LogicalValue>,
}

impl<'a> Node<'a> {
    pub fn object_child(self, projected: &'a Value, key: &str) -> Self {
        Self {
            projected,
            logical: self
                .logical
                .and_then(LogicalValue::as_object)
                .and_then(|object| object.get(key)),
        }
    }

    pub fn array_child(self, projected: &'a Value, index: usize) -> Self {
        Self {
            projected,
            logical: self
                .logical
                .and_then(LogicalValue::as_array)
                .and_then(|array| array.get(index)),
        }
    }
}

#[derive(Default)]
pub(super) struct Paths {
    source: String,
    // An unordered array may pair nodes under different index prefixes.
    target: Option<String>,
}

impl Paths {
    pub fn new(source: &str, target: &str) -> Self {
        Self {
            source: source.to_owned(),
            target: (source != target).then(|| target.to_owned()),
        }
    }

    pub fn pair(&self) -> (&str, &str) {
        (&self.source, self.target.as_deref().unwrap_or(&self.source))
    }

    pub fn at_key<T>(&mut self, key: &str, visit: impl FnOnce(&mut Self) -> T) -> T {
        self.at_child(|path| traffic_value::path::push_segment(path, key), visit)
    }

    pub fn at_index<T>(&mut self, index: usize, visit: impl FnOnce(&mut Self) -> T) -> T {
        self.at_child(
            |path| write!(path, "/{index}").expect("writing to a String is infallible"),
            visit,
        )
    }

    fn at_child<T>(
        &mut self,
        append: impl FnOnce(&mut String),
        visit: impl FnOnce(&mut Self) -> T,
    ) -> T {
        let prefix = self.source.len();
        append(&mut self.source);
        let target_prefix = self.target.as_mut().map(|target| {
            let prefix_len = target.len();
            target.push_str(&self.source[prefix..]);
            prefix_len
        });

        let result = visit(self);
        self.source.truncate(prefix);
        if let (Some(target), Some(prefix)) = (&mut self.target, target_prefix) {
            target.truncate(prefix);
        }
        result
    }
}
