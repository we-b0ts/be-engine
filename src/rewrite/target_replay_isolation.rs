use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use proc_macro2::TokenTree;
use serde::Serialize;
use syn::visit::{self, Visit};
use syn::{Attribute, Item, Lit, LitByteStr, LitStr, Meta};

pub(super) const GATE_NAME: &str = "replay-isolation";
pub(super) const GATE_VERSION: &str = "replay-isolation-v2";

const MAX_REPORTED_VIOLATIONS: usize = 64;
const IGNORED_DIRECTORIES: &[&str] = &[
    ".git",
    ".traffic-e2e",
    "benches",
    "examples",
    "fixtures",
    "node_modules",
    "target",
    "testdata",
    "tests",
    "vendor",
];

#[derive(Debug, Serialize)]
pub(super) struct ReplayIsolationReport {
    schema_version: u8,
    gate: &'static str,
    status: ReplayIsolationStatus,
    scanned_files: usize,
    violations: Vec<ReplayIsolationViolation>,
    omitted_violations: usize,
}

impl ReplayIsolationReport {
    pub(super) fn passed(&self) -> bool {
        matches!(self.status, ReplayIsolationStatus::Passed)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReplayIsolationStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct ReplayIsolationViolation {
    file: PathBuf,
    line: usize,
    column: usize,
    rule: &'static str,
    matched: &'static str,
    reason: &'static str,
    required_change: &'static str,
}

#[derive(Clone, Copy)]
struct ForbiddenMarker {
    rule: &'static str,
    marker: &'static str,
    reason: &'static str,
    required_change: &'static str,
}

const FORBIDDEN_MARKERS: &[ForbiddenMarker] = &[
    ForbiddenMarker {
        rule: "replay_hostname",
        marker: ".trp.test",
        reason: "production code depends on a replay-only synthetic hostname",
        required_change: "obtain the dependency address through genuine runtime configuration or source-compatible discovery",
    },
    ForbiddenMarker {
        rule: "fake_ip_range",
        marker: "198.18.",
        reason: "production code depends on the replay fake-IP range",
        required_change: "remove the replay address and use the dependency address supplied by the real runtime contract",
    },
    ForbiddenMarker {
        rule: "fake_ip_range",
        marker: "198.19.",
        reason: "production code depends on the replay fake-IP range",
        required_change: "remove the replay address and use the dependency address supplied by the real runtime contract",
    },
    ForbiddenMarker {
        rule: "local_runtime_path",
        marker: ".traffic-e2e/local",
        reason: "production code reads traffic-e2e private runtime state",
        required_change: "remove the private runtime-state dependency and use an application-owned input contract",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "expected-response.json",
        reason: "production code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "expected-response-after.json",
        reason: "production code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "dependencies.jsonl",
        reason: "production code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "dependencies-debug.jsonl",
        reason: "production code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "assertions.json",
        reason: "production code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "fake_dns_registry.json",
        reason: "production code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "replay-progress.yaml",
        reason: "production code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "comparison-progress.yaml",
        reason: "production code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
];

pub(super) fn inspect(target_root: &Path, pr_base: &str) -> Result<ReplayIsolationReport> {
    let source_files = changed_production_rust_files(target_root, pr_base)?;
    let mut violations = Vec::new();
    for source_file in &source_files {
        let source = fs::read_to_string(source_file)
            .with_context(|| format!("failed to read production Rust source {source_file:?}"))?;
        let syntax = syn::parse_file(&source)
            .with_context(|| format!("failed to parse production Rust source {source_file:?}"))?;
        let relative = source_file
            .strip_prefix(target_root)
            .unwrap_or(source_file)
            .to_path_buf();
        let mut visitor = ReplayIsolationVisitor {
            file: relative,
            violations: &mut violations,
        };
        visitor.visit_file(&syntax);
    }
    violations.sort();
    let omitted_violations = violations.len().saturating_sub(MAX_REPORTED_VIOLATIONS);
    violations.truncate(MAX_REPORTED_VIOLATIONS);
    let status = if violations.is_empty() && omitted_violations == 0 {
        ReplayIsolationStatus::Passed
    } else {
        ReplayIsolationStatus::Failed
    };
    Ok(ReplayIsolationReport {
        schema_version: 1,
        gate: GATE_NAME,
        status,
        scanned_files: source_files.len(),
        violations,
        omitted_violations,
    })
}

fn changed_production_rust_files(target_root: &Path, pr_base: &str) -> Result<Vec<PathBuf>> {
    let base_ref = resolve_pr_base(target_root, pr_base)?;
    let merge_base = git_text(target_root, &["merge-base", "HEAD", &base_ref])?;
    let mut files = BTreeSet::new();
    collect_changed_paths(
        target_root,
        &git_bytes(
            target_root,
            &[
                "diff",
                "--no-ext-diff",
                "--name-only",
                "-z",
                "--diff-filter=ACMRT",
                merge_base.trim(),
                "--",
            ],
        )?,
        &mut files,
    )?;
    collect_changed_paths(
        target_root,
        &git_bytes(
            target_root,
            &["ls-files", "--others", "--exclude-standard", "-z", "--"],
        )?,
        &mut files,
    )?;
    Ok(files.into_iter().collect())
}

fn resolve_pr_base(target_root: &Path, pr_base: &str) -> Result<String> {
    for candidate in [
        format!("refs/heads/{pr_base}"),
        format!("refs/remotes/origin/{pr_base}"),
    ] {
        let status = Command::new("git")
            .arg("-C")
            .arg(target_root)
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("{candidate}^{{commit}}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("failed to resolve pull-request base {candidate:?}"))?;
        if status.success() {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "pr_base {pr_base:?} does not exist as a local branch or origin remote-tracking branch"
    )
}

fn collect_changed_paths(
    target_root: &Path,
    raw: &[u8],
    files: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for raw_path in raw.split(|byte| *byte == 0).filter(|path| !path.is_empty()) {
        let relative =
            std::str::from_utf8(raw_path).context("changed repository path is not UTF-8")?;
        let relative = Path::new(relative);
        if !is_production_rust_path(relative) {
            continue;
        }
        let path = target_root.join(relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect changed source {path:?}"));
            }
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            continue;
        }
        files.insert(path);
    }
    Ok(())
}

fn is_production_rust_path(path: &Path) -> bool {
    if path.extension().is_none_or(|extension| extension != "rs") {
        return false;
    }
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            return false;
        };
        let component = component.to_string_lossy();
        if IGNORED_DIRECTORIES.contains(&component.as_ref()) {
            return false;
        }
        if component == "src" {
            return true;
        }
    }
    false
}

fn git_text(target_root: &Path, args: &[&str]) -> Result<String> {
    let raw = git_bytes(target_root, args)?;
    String::from_utf8(raw).context("Git output is not UTF-8")
}

fn git_bytes(target_root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(args)
        .output()
        .context("failed to inspect changed target files with Git")?;
    anyhow::ensure!(
        output.status.success(),
        "Git command failed while inspecting changed target files: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

struct ReplayIsolationVisitor<'a> {
    file: PathBuf,
    violations: &'a mut Vec<ReplayIsolationViolation>,
}

impl ReplayIsolationVisitor<'_> {
    fn inspect_text(&mut self, value: &str, line: usize, column: usize) {
        let lower = value.to_ascii_lowercase();
        for forbidden in FORBIDDEN_MARKERS {
            if lower.contains(forbidden.marker) {
                self.violations.push(ReplayIsolationViolation {
                    file: self.file.clone(),
                    line,
                    column,
                    rule: forbidden.rule,
                    matched: forbidden.marker,
                    reason: forbidden.reason,
                    required_change: forbidden.required_change,
                });
            }
        }
    }

    fn inspect_lit_str(&mut self, literal: &LitStr) {
        let start = literal.span().start();
        self.inspect_text(&literal.value(), start.line, start.column + 1);
    }

    fn inspect_lit_byte_str(&mut self, literal: &LitByteStr) {
        let Ok(value) = String::from_utf8(literal.value()) else {
            return;
        };
        let start = literal.span().start();
        self.inspect_text(&value, start.line, start.column + 1);
    }

    fn inspect_token_tree(&mut self, token: &TokenTree) {
        match token {
            TokenTree::Group(group) => {
                for nested in group.stream() {
                    self.inspect_token_tree(&nested);
                }
            }
            TokenTree::Literal(literal) => {
                let Ok(parsed) = syn::parse_str::<Lit>(&literal.to_string()) else {
                    return;
                };
                let start = literal.span().start();
                match parsed {
                    Lit::Str(value) => {
                        self.inspect_text(&value.value(), start.line, start.column + 1)
                    }
                    Lit::ByteStr(value) => {
                        if let Ok(value) = String::from_utf8(value.value()) {
                            self.inspect_text(&value, start.line, start.column + 1);
                        }
                    }
                    _ => {}
                }
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for ReplayIsolationVisitor<'_> {
    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        if attribute.path().is_ident("doc") {
            return;
        }
        match &attribute.meta {
            Meta::Path(_) => {}
            Meta::List(list) => {
                for token in list.tokens.clone() {
                    self.inspect_token_tree(&token);
                }
            }
            Meta::NameValue(name_value) => self.visit_expr(&name_value.value),
        }
    }

    fn visit_item(&mut self, item: &'ast Item) {
        if item_attributes(item).is_some_and(test_only) {
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if impl_item_attributes(item).is_some_and(test_only) {
            return;
        }
        visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if trait_item_attributes(item).is_some_and(test_only) {
            return;
        }
        visit::visit_trait_item(self, item);
    }

    fn visit_foreign_item(&mut self, item: &'ast syn::ForeignItem) {
        if foreign_item_attributes(item).is_some_and(test_only) {
            return;
        }
        visit::visit_foreign_item(self, item);
    }

    fn visit_lit_str(&mut self, literal: &'ast LitStr) {
        self.inspect_lit_str(literal);
    }

    fn visit_lit_byte_str(&mut self, literal: &'ast LitByteStr) {
        self.inspect_lit_byte_str(literal);
    }

    fn visit_macro(&mut self, expression: &'ast syn::Macro) {
        for token in expression.tokens.clone() {
            self.inspect_token_tree(&token);
        }
    }
}

fn item_attributes(item: &Item) -> Option<&[Attribute]> {
    match item {
        Item::Const(item) => Some(&item.attrs),
        Item::Enum(item) => Some(&item.attrs),
        Item::ExternCrate(item) => Some(&item.attrs),
        Item::Fn(item) => Some(&item.attrs),
        Item::ForeignMod(item) => Some(&item.attrs),
        Item::Impl(item) => Some(&item.attrs),
        Item::Macro(item) => Some(&item.attrs),
        Item::Mod(item) => Some(&item.attrs),
        Item::Static(item) => Some(&item.attrs),
        Item::Struct(item) => Some(&item.attrs),
        Item::Trait(item) => Some(&item.attrs),
        Item::TraitAlias(item) => Some(&item.attrs),
        Item::Type(item) => Some(&item.attrs),
        Item::Union(item) => Some(&item.attrs),
        Item::Use(item) => Some(&item.attrs),
        Item::Verbatim(_) => None,
        _ => None,
    }
}

fn impl_item_attributes(item: &syn::ImplItem) -> Option<&[Attribute]> {
    match item {
        syn::ImplItem::Const(item) => Some(&item.attrs),
        syn::ImplItem::Fn(item) => Some(&item.attrs),
        syn::ImplItem::Macro(item) => Some(&item.attrs),
        syn::ImplItem::Type(item) => Some(&item.attrs),
        syn::ImplItem::Verbatim(_) => None,
        _ => None,
    }
}

fn trait_item_attributes(item: &syn::TraitItem) -> Option<&[Attribute]> {
    match item {
        syn::TraitItem::Const(item) => Some(&item.attrs),
        syn::TraitItem::Fn(item) => Some(&item.attrs),
        syn::TraitItem::Macro(item) => Some(&item.attrs),
        syn::TraitItem::Type(item) => Some(&item.attrs),
        syn::TraitItem::Verbatim(_) => None,
        _ => None,
    }
}

fn foreign_item_attributes(item: &syn::ForeignItem) -> Option<&[Attribute]> {
    match item {
        syn::ForeignItem::Fn(item) => Some(&item.attrs),
        syn::ForeignItem::Macro(item) => Some(&item.attrs),
        syn::ForeignItem::Static(item) => Some(&item.attrs),
        syn::ForeignItem::Type(item) => Some(&item.attrs),
        syn::ForeignItem::Verbatim(_) => None,
        _ => None,
    }
}

fn test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test")
            || (attribute.path().is_ident("cfg") && meta_requires_test(&attribute.meta))
    })
}

fn meta_requires_test(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) if list.path.is_ident("cfg") || list.path.is_ident("all") => list
            .parse_args_with(syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated)
            .is_ok_and(|nested| nested.iter().any(meta_requires_test)),
        Meta::List(list) if list.path.is_ident("any") => list
            .parse_args_with(syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated)
            .is_ok_and(|nested| !nested.is_empty() && nested.iter().all(meta_requires_test)),
        Meta::List(_) | Meta::NameValue(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_replay_literals_without_echoing_the_complete_value() {
        let target = target_with_source("pub fn value() -> u8 { 1 }\n");
        fs::write(
            target.path().join("src/lib.rs"),
            "pub const CACHE: &str = \"vintage-node-secret.trp.test:15138\";\n",
        )
        .unwrap();

        let report = inspect(target.path(), "integration").unwrap();
        let value = serde_json::to_value(report).unwrap();

        assert_eq!(value["status"], "failed");
        assert_eq!(value["violations"][0]["file"], "src/lib.rs");
        assert_eq!(value["violations"][0]["line"], 1);
        assert_eq!(value["violations"][0]["matched"], ".trp.test");
        assert!(!value.to_string().contains("vintage-node-secret"));
    }

    #[test]
    fn ignores_comments_docs_test_modules_and_non_production_trees() {
        let target = target_with_source("pub fn value() -> u8 { 1 }\n");
        fs::create_dir_all(target.path().join("tests")).unwrap();
        fs::write(
            target.path().join("src/lib.rs"),
            "// cache.trp.test\n\
             /// docs mention dependencies.jsonl\n\
             pub fn value() -> &'static str { \"normal.example\" }\n\
             #[cfg(test)]\n\
             mod tests { const CACHE: &str = \"cache.trp.test\"; }\n\
             struct Client;\n\
             impl Client { #[cfg(test)] fn replay() { let _ = \"198.18.1.2\"; } }\n",
        )
        .unwrap();
        fs::write(
            target.path().join("tests/integration.rs"),
            "const CACHE: &str = \"cache.trp.test\";\n",
        )
        .unwrap();

        let report = inspect(target.path(), "integration").unwrap();

        assert!(report.passed());
        assert_eq!(report.scanned_files, 1);
    }

    #[test]
    fn checks_literals_in_production_attributes() {
        let target = target_with_source("pub fn value() -> u8 { 1 }\n");
        fs::write(
            target.path().join("src/lib.rs"),
            "#[link(name = \"cache.trp.test\")] extern \"C\" {}\n",
        )
        .unwrap();

        let report = inspect(target.path(), "integration").unwrap();
        let value = serde_json::to_value(report).unwrap();

        assert_eq!(value["violations"][0]["rule"], "replay_hostname");
    }

    #[test]
    fn scans_nested_production_sources_and_macro_literals() {
        let target = target_with_source("pub fn value() -> u8 { 1 }\n");
        fs::create_dir_all(target.path().join("crates/client/src")).unwrap();
        fs::create_dir_all(target.path().join("apps/worker/src")).unwrap();
        fs::write(
            target.path().join("crates/client/src/lib.rs"),
            "const FAKE: &str = concat!(\"198.18.\", \"1.2\");\n",
        )
        .unwrap();
        fs::write(
            target.path().join("apps/worker/src/main.rs"),
            "const DATA: &[u8] = b\"dependencies.jsonl\";\n",
        )
        .unwrap();

        let report = inspect(target.path(), "integration").unwrap();
        let value = serde_json::to_value(report).unwrap();

        assert_eq!(value["scanned_files"], 2);
        assert_eq!(value["violations"].as_array().unwrap().len(), 2);
        assert_eq!(value["violations"][0]["rule"], "recording_artifact");
        assert_eq!(value["violations"][1]["rule"], "fake_ip_range");
    }

    #[test]
    fn ignores_replay_literals_unchanged_from_the_pr_base() {
        let target = target_with_source(
            "pub const LEGACY: &str = \"vintage-node-legacy.trp.test:15138\";\n",
        );
        fs::write(
            target.path().join("src/new.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .unwrap();

        let report = inspect(target.path(), "integration").unwrap();

        assert!(report.passed());
        assert_eq!(report.scanned_files, 1);
    }

    #[test]
    fn compares_an_independent_worktree_with_the_shared_pr_base() {
        let root = tempfile::tempdir().unwrap();
        let primary = root.path().join("primary");
        let worker = root.path().join("worker");
        initialize_base(&primary, "pub fn value() -> u8 { 1 }\n");
        git(
            &primary,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "feature",
                worker.to_str().unwrap(),
                "integration",
            ],
        );
        fs::write(
            worker.join("src/lib.rs"),
            "pub const CACHE: &str = \"cache.trp.test\";\n",
        )
        .unwrap();

        let report = inspect(&worker, "integration").unwrap();

        assert!(!report.passed());
        assert_eq!(report.scanned_files, 1);
    }

    fn target_with_source(source: &str) -> tempfile::TempDir {
        let target = tempfile::tempdir().unwrap();
        initialize_base(target.path(), source);
        git(target.path(), &["switch", "-q", "-c", "feature"]);
        target
    }

    fn initialize_base(target: &Path, source: &str) {
        fs::create_dir_all(target.join("src")).unwrap();
        fs::write(target.join("src/lib.rs"), source).unwrap();
        git(target, &["init", "-q", "-b", "integration"]);
        git(target, &["add", "."]);
        git(
            target,
            &[
                "-c",
                "user.name=Traffic E2E Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-q",
                "-m",
                "baseline",
            ],
        );
    }

    fn git(target: &Path, args: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target)
                .args(args)
                .status()
                .unwrap()
                .success(),
            "git command failed: {args:?}"
        );
    }
}
