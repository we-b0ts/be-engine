//! Select authenticated logical strings for codecs that retain raw wire slots.
use std::fmt::Write;

use traffic_contract::compare::AnchorClocks;
use traffic_value::Value;

use super::{Carrier, Matcher};

impl Matcher {
    pub fn matching_string_paths(
        &self,
        source: &Value,
        target: &Value,
        clocks: AnchorClocks,
    ) -> Vec<String> {
        let mut selection = Selection {
            matcher: self,
            clocks,
            remaining: 16_384,
            paths: Vec::new(),
        };
        selection.visit(source, target, &mut String::new(), 0);
        selection.paths
    }
}

struct Selection<'a> {
    matcher: &'a Matcher,
    clocks: AnchorClocks,
    remaining: usize,
    paths: Vec<String>,
}

impl Selection<'_> {
    fn visit(&mut self, source: &Value, target: &Value, path: &mut String, depth: usize) {
        if self.remaining == 0 || depth > 128 || std::ptr::eq(source, target) {
            return;
        }
        self.remaining -= 1;
        let length = path.len();
        match (source, target) {
            (Value::String(a), Value::String(b)) if a != b => {
                if self
                    .matcher
                    .compare(a, b, Carrier::Value, self.clocks)
                    .is_some()
                {
                    self.paths.push(path.clone());
                }
            }
            (Value::Object(a), Value::Object(b)) if a.len() == b.len() => {
                for ((name, source), (other, target)) in a.iter().zip(b) {
                    if name != other || self.remaining == 0 {
                        break;
                    }
                    path.push('/');
                    path.push_str(&traffic_value::path::escape(name));
                    self.visit(source, target, path, depth + 1);
                    path.truncate(length);
                }
            }
            (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
                for (index, (source, target)) in a.iter().zip(b).enumerate() {
                    if self.remaining == 0 {
                        break;
                    }
                    write!(path, "/{index}").expect("write to string");
                    self.visit(source, target, path, depth + 1);
                    path.truncate(length);
                }
            }
            _ => {}
        }
    }
}
