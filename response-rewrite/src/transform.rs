//! Explicit document edits selected by the same compiled wildcard paths as addresses.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::selector::Selector;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Transform {
    Remove { path: String },
    Set { path: String, value: Value },
    Take { path: String, count: usize },
}

#[derive(Debug)]
pub(crate) struct CompiledTransform {
    selector: Selector,
    action: Transform,
}

impl CompiledTransform {
    pub fn compile(action: &Transform) -> Result<Self> {
        let path = match action {
            Transform::Remove { path } | Transform::Set { path, .. } => path,
            Transform::Take { path, count } => {
                ensure!(*count <= 4096, "response take count exceeds its budget");
                path
            }
        };
        ensure!(!path.is_empty(), "response transforms require a child path");
        if let Transform::Set { value, .. } = action {
            ensure!(
                serde_json::to_vec(value)?.len() <= 65536,
                "response set value exceeds its budget"
            );
        }
        Ok(Self {
            selector: Selector::compile(path)?,
            action: action.clone(),
        })
    }

    pub fn apply(&self, document: &mut Value) -> Result<bool> {
        let mut paths = self.selector.select(document)?;
        // Descendants precede parents and later array indexes precede earlier
        // ones, so removing one selection cannot retarget another selection.
        paths.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| b.cmp(a)));
        let mut changed = false;
        for path in paths {
            match &self.action {
                Transform::Remove { .. } => {
                    let (parent, key) = path
                        .rsplit_once('/')
                        .context("response remove has no parent")?;
                    let key = key.replace("~1", "/").replace("~0", "~");
                    match document
                        .pointer_mut(parent)
                        .context("response remove parent disappeared")?
                    {
                        Value::Object(object) => {
                            changed |= object.remove(&key).is_some();
                        }
                        Value::Array(array) => {
                            let index = key.parse::<usize>()?;
                            ensure!(index < array.len(), "response remove index disappeared");
                            array.remove(index);
                            changed = true;
                        }
                        _ => anyhow::bail!("response remove requires an object or array"),
                    }
                }
                Transform::Set { value, .. } => {
                    let selected = document
                        .pointer_mut(&path)
                        .context("response set path disappeared")?;
                    changed |= selected != value;
                    *selected = value.clone();
                }
                Transform::Take { count, .. } => {
                    let selected = document
                        .pointer_mut(&path)
                        .and_then(Value::as_array_mut)
                        .context("response take requires an array")?;
                    changed |= selected.len() > *count;
                    selected.truncate(*count);
                }
            }
        }
        Ok(changed)
    }
}
