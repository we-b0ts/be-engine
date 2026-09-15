use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use super::model::{ReviewFinding, ReviewRule};
use crate::rewrite::{fingerprint, source_diff};

pub(super) fn scan(
    root: &Path,
    base: &str,
) -> Result<(BTreeMap<std::path::PathBuf, String>, Vec<ReviewFinding>)> {
    let diff = source_diff::changed_rust_lines(root, base)?;
    let mut files = BTreeMap::new();
    let mut findings = Vec::new();
    for file in diff
        .files
        .iter()
        .filter(|path| source_diff::is_production_rust_path(path))
    {
        let source = std::fs::read_to_string(source_diff::managed_file_path(root, file)?)?;
        files.insert(file.clone(), fingerprint::id(&[&source]));
        let lines = source.lines().count();
        if lines > 1000 {
            findings.push(finding(file, 1, 1, ReviewRule::FileLines, format!("complete file has {lines} lines; split responsibilities until the file has at most 1000 lines")));
        }
        let added = diff
            .lines
            .iter()
            .filter(|line| &line.file == file)
            .map(|line| line.line)
            .collect();
        findings.extend(scan_source(file, &source, added));
    }
    Ok((files, findings))
}

fn scan_source(file: &Path, source: &str, added: BTreeSet<usize>) -> Vec<ReviewFinding> {
    let syntax = match syn::parse_file(source) {
        Ok(syntax) => syntax,
        Err(error) => {
            return vec![finding(
                file,
                error.span().start().line,
                error.span().start().column + 1,
                ReviewRule::RustSyntax,
                format!("cannot review invalid Rust: {error}"),
            )];
        }
    };
    let mut imports = Imports::default();
    imports.visit_file(&syntax);
    let mut scanner = Scanner {
        file,
        added,
        imports: imports.names,
        findings: Vec::new(),
    };
    scanner.visit_file(&syntax);
    scanner
        .findings
        .sort_by_key(|f| (f.line, f.column, f.id.clone()));
    scanner.findings.dedup_by(|a, b| a.id == b.id);
    scanner.findings
}

#[derive(Default)]
struct Imports {
    names: BTreeMap<String, String>,
}

impl<'ast> Visit<'ast> for Imports {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        imports(&item.tree, "", &mut self.names);
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !test_only(&item.attrs) {
            visit::visit_item_fn(self, item);
        }
    }
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !test_only(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }
}

fn imports(tree: &syn::UseTree, prefix: &str, names: &mut BTreeMap<String, String>) {
    match tree {
        syn::UseTree::Path(path) => {
            imports(&path.tree, &format!("{prefix}{}::", path.ident), names)
        }
        syn::UseTree::Name(name) => {
            names.insert(name.ident.to_string(), format!("{prefix}{}", name.ident));
        }
        syn::UseTree::Rename(name) => {
            names.insert(name.rename.to_string(), format!("{prefix}{}", name.ident));
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                imports(item, prefix, names);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

struct Scanner<'a> {
    file: &'a Path,
    added: BTreeSet<usize>,
    imports: BTreeMap<String, String>,
    findings: Vec<ReviewFinding>,
}

impl Scanner<'_> {
    fn record(&mut self, span: proc_macro2::Span, rule: ReviewRule) {
        if !self
            .added
            .range(span.start().line..=span.end().line)
            .next()
            .is_some()
        {
            return;
        }
        let message = match rule {
            ReviewRule::SpawnOwnership => {
                "trace the actual startup entry and every caller; request-triggered tasks are rejected, including callbacks registered during startup"
            }
            _ => unreachable!(),
        };
        self.findings.push(finding(
            self.file,
            span.start().line,
            span.start().column + 1,
            rule,
            message.into(),
        ));
    }

    fn resolved(&self, path: &syn::Path) -> String {
        let mut names = path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>();
        if let Some(first) = names.first_mut()
            && let Some(imported) = self.imports.get(first)
        {
            *first = imported.clone();
        }
        names.join("::")
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !test_only(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !test_only(&item.attrs) {
            visit::visit_item_fn(self, item);
        }
    }
    fn visit_path(&mut self, path: &'ast syn::Path) {
        let name = self.resolved(path);
        if matches!(name.as_str(), "tokio::spawn" | "tokio::task::spawn") {
            self.record(path.span(), ReviewRule::SpawnOwnership);
        }
        visit::visit_path(self, path);
    }
    // Macro expansion is intentionally outside this policy.
    fn visit_macro(&mut self, _item: &'ast syn::Macro) {}
}

fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Path>()
                    .is_ok_and(|path| path.is_ident("test")))
    })
}

pub(super) fn finding(
    file: &Path,
    line: usize,
    column: usize,
    rule: ReviewRule,
    message: String,
) -> ReviewFinding {
    let id = fingerprint::id(&[
        "source-review-finding-v1",
        &file.to_string_lossy(),
        &line.to_string(),
        &column.to_string(),
        &format!("{rule:?}"),
    ]);
    ReviewFinding {
        id,
        file: file.to_path_buf(),
        line,
        column,
        rule,
        message,
    }
}

pub(super) fn file_hash(root: &Path, file: &Path) -> Result<String> {
    let text = std::fs::read_to_string(source_diff::managed_file_path(root, file)?)
        .with_context(|| format!("cannot read review evidence {}", file.display()))?;
    Ok(fingerprint::id(&[&text]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_json_values_imports_aliases_and_maps_are_allowed() {
        let source = r#"
use serde_json::Value;
use serde_json::Value as Json;
use serde_json as json;
type Payload = serde_json::Value;
fn run(value: Value, alias: Json, renamed: json::Value) {
    let _: serde_json::Map<String, serde_json::Value>;
    let _ = serde_json::Value::Null;
    let _ = serde_json::json!({"ok": true});
}
"#;
        assert!(scan_source(Path::new("src/lib.rs"), source, (1..=20).collect()).is_empty());
    }

    #[test]
    fn spawn_aliases_are_found_but_json_values_and_comments_are_allowed() {
        let source = "use serde_json::Value as Json;\nuse tokio::{spawn as launch};\nfn run() {\n let _: Json;\n launch(async {});\n let _ = serde_json::json!({\"ok\": true});\n // serde_json::Value tokio::spawn\n}\n#[cfg(test)] mod tests { fn test() { let _: serde_json::Value; } }\n";
        let findings = scan_source(Path::new("src/lib.rs"), source, (1..=20).collect());
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule == ReviewRule::JsonValue)
                .count(),
            0
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule == ReviewRule::SpawnOwnership)
                .count(),
            1
        );
        assert!(scan_source(Path::new("src/lib.rs"), source, BTreeSet::from([6, 7])).is_empty());
    }
}
